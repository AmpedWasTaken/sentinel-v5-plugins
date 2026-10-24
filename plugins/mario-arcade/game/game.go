// Package game implements a deterministic, turn-based terminal platformer.
// It has no terminal, file, network, or Sentinel runtime dependencies.
package game

import (
 "errors"
 "fmt"
 "strings"
)

const (
 Height=9
 ViewWidth=37
 saveVersion=1
)

type Point struct { X int; Y int }
type span struct { Start, End int }
type ledge struct { Start, End, Y int }
type stage struct {
 Name string
 Width int
 Gaps []span
 Platforms []ledge
 Coins []Point
 Enemies []Point
}

var stages=[]stage{
 {"Copper Meadow",70,[]span{{15,18},{35,38},{56,59}},[]ledge{{6,11,4},{26,31,5},{46,51,4}},
  []Point{{7,7},{17,5},{25,7},{28,4},{42,7},{49,5},{63,7}},[]Point{{11,7},{32,7},{52,7}}},
 {"Neon Caverns",83,[]span{{12,16},{31,34},{54,58},{68,71}},[]ledge{{3,8,4},{24,29,5},{45,50,4},{73,77,4}},
  []Point{{8,7},{14,5},{23,7},{33,5},{47,7},{55,5},{65,7},{73,7}},[]Point{{21,7},{43,7},{61,7}}},
 {"Signal Fortress",93,[]span{{17,21},{39,43},{61,65},{77,81}},[]ledge{{5,11,4},{27,33,5},{48,54,4},{83,88,4}},
  []Point{{6,7},{19,5},{30,7},{40,5},{50,7},{63,5},{71,7},{79,5},{87,7}},[]Point{{13,7},{34,7},{57,7},{72,7}}},
}

// State is a shared, server-managed arcade save: the persistent RPC host
// does not expose an authenticated actor identity to plugin handlers.
type State struct {
 Version int
 Level int
 X int
 Y int
 Velocity int
 Lives int
 Score int
 Turns int
 Collected []Point
 Defeated []Point
 Over bool
 Won bool
 Message string
}

func New() State {
 return State{Version:saveVersion,Level:1,X:2,Y:Height-2,Lives:3,Message:"Welcome! Jump over pits, collect coins, reach the flag."}
}
func (s State) Valid()bool{
 if s.Version!=saveVersion||s.Level<1||s.Level>len(stages)||s.Lives<0||s.Lives>3||
  s.Score<0||s.Score>10000000||s.Turns<0||s.Turns>10000000||s.Velocity < -3||s.Velocity>3{return false}
 if s.X<0||s.X>=stages[s.Level-1].Width||s.Y<0||s.Y>=Height{return false}
 if len(s.Collected)>64||len(s.Defeated)>32||len(s.Message)>240{return false}
 for _,p:=range append(append([]Point(nil),s.Collected...),s.Defeated...){
  if p.X<0||p.X>=stages[s.Level-1].Width||p.Y<0||p.Y>=Height{return false}
 }
 return true
}
func contains(p Point,items []Point)bool{
 for _,item:=range items{if item==p{return true}}
 return false
}
func (s State) tile(x,y int)byte{
 level:=stages[s.Level-1]
 if x<0||x>=level.Width||y<0||y>=Height{return ' '}
 if y==Height-1{
  for _,g:=range level.Gaps{if x>=g.Start&&x<g.End{return ' '}}
  return '='
 }
 for _,p:=range level.Platforms{if y==p.Y&&x>=p.Start&&x<p.End{return '#'}}
 pos:=Point{x,y}
 if contains(pos,level.Coins)&&!contains(pos,s.Collected){return '$'}
 if contains(pos,level.Enemies)&&!contains(pos,s.Defeated){return 'X'}
 if x==level.Width-3&&y>=4&&y<=Height-2{return 'F'}
 return ' '
}
func solid(c byte)bool{return c=='='||c=='#'}
func (s State) supported()bool{return solid(s.tile(s.X,s.Y+1))}
func (s *State) loseLife(reason string){
 s.Lives--
 s.Velocity=0
 if s.Lives<=0{
  s.Lives=0;s.Over=true
  s.Message="GAME OVER: "+reason+". Use mario-arcade new to retry."
  return
 }
 s.X=2;s.Y=Height-2
 s.Message=fmt.Sprintf("%s! Respawned with %d lives.",reason,s.Lives)
}
func (s *State) touch()bool{
 switch s.tile(s.X,s.Y){
 case '$':
  s.Collected=append(s.Collected,Point{s.X,s.Y});s.Score+=100
  s.Message="Coin collected! +100 points."
 case 'X':
  s.loseLife("Enemy collision")
  return true
 case 'F':
  if s.Level==len(stages){
   s.Won=true;s.Over=true
   s.Message="YOU WIN! All three worlds cleared. Use mario-arcade new to replay."
   return true
  }
  s.Level++;s.X=2;s.Y=Height-2;s.Velocity=0
  s.Collected=nil;s.Defeated=nil;s.Score+=500
  s.Message="LEVEL COMPLETE! +500 points. Welcome to "+stages[s.Level-1].Name+"."
  return true
 }
 return false
}

// Step advances one physics tick per SSH command. Native realtime key input
// is not exposed by the current bounded, JSON-framed Sentinel plugin protocol.
func (s *State) Step(action string)error{
 if action=="new"{*s=New();return nil}
 if action=="play"||action=="show"{return nil}
 dx,jump:=0,false
 switch action{
 case "left":dx=-1
 case "right":dx=1
 case "jump":jump=true
 case "jump-left":dx=-1;jump=true
 case "jump-right":dx=1;jump=true
 case "wait":
 default:return errors.New("unknown action: play, left, right, jump, jump-left, jump-right, wait or new")
 }
 if s.Over{s.Message="Game finished. Run mario-arcade new to restart.";return nil}
 s.Turns++;s.Message="Move to the flag. Coins=$, enemies=X, goal=F."
 if jump&&s.supported(){s.Velocity=-2}else if s.Velocity<2{s.Velocity++}
 if s.Velocity<0{
  steps:=-s.Velocity
  for i:=0;i<steps;i++{
   if s.Y==0||solid(s.tile(s.X,s.Y-1)){s.Velocity=0;break}
   s.Y--
   if s.touch(){return nil}
  }
 }
 nx:=s.X+dx
 if nx>=0&&nx<stages[s.Level-1].Width&&!solid(s.tile(nx,s.Y)){s.X=nx}
 if s.touch(){return nil}
 if s.Velocity>0{
  steps:=s.Velocity
  for i:=0;i<steps;i++{
   ny:=s.Y+1
   if ny>=Height{s.loseLife("Fell into a pit");return nil}
   if solid(s.tile(s.X,ny)){s.Velocity=0;break}
   if s.tile(s.X,ny)=='X'{
    s.Defeated=append(s.Defeated,Point{s.X,ny})
    s.Score+=200;s.Velocity=-1
    s.Message="Enemy stomped! +200 points."
    return nil
   }
   s.Y=ny
   if s.touch(){return nil}
  }
 }
 if s.Y==Height-1&&!s.supported()&&s.Velocity>=0{s.loseLife("Fell into a pit")}
 return nil
}

// Render emits one-line ASCII fields; SML renders them without ANSI escape codes.
func (s State) Render()map[string]string{
 level:=stages[s.Level-1]
 start:=s.X-ViewWidth/3
 if start<0{start=0}
 if start>level.Width-ViewWidth{start=level.Width-ViewWidth}
 if start<0{start=0}
 values:=map[string]string{
  "level":fmt.Sprintf("%d / %d  %s",s.Level,len(stages),level.Name),
  "lives":fmt.Sprintf("%d",s.Lives),
  "score":fmt.Sprintf("%d",s.Score),
  "turns":fmt.Sprintf("%d",s.Turns),
  "coins":fmt.Sprintf("%d",len(s.Collected)),
  "message":s.Message,
  "camera":fmt.Sprintf("%02d-%02d",start+1,start+ViewWidth),
 }
 for y:=0;y<Height;y++{
  row:=make([]byte,ViewWidth)
  for x:=0;x<ViewWidth;x++{
   wx:=start+x
   row[x]=s.tile(wx,y)
   if !s.Over&&wx==s.X&&y==s.Y{row[x]='@'}
  }
  values[fmt.Sprintf("row%d",y)]=string(row)
 }
 return values
}
func (s State) Text()string{
 v:=s.Render()
 lines:=[]string{"SENTINEL JUMP / "+v["level"],
  fmt.Sprintf("LIVES %s  SCORE %s  TURNS %s  CAMERA %s",v["lives"],v["score"],v["turns"],v["camera"])}
 for y:=0;y<Height;y++{lines=append(lines,v[fmt.Sprintf("row%d",y)])}
 lines=append(lines,s.Message,"Use: mario-arcade [left|right|jump|jump-left|jump-right|wait|show|new]")
 return strings.Join(lines,"\n")
}

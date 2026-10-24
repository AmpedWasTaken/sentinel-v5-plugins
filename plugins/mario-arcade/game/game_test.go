package game

import (
 "strings"
 "testing"
)

func TestInitializationAndRendering(t *testing.T){
 s:=New()
 if !s.Valid(){t.Fatal("new game invalid")}
 v:=s.Render()
 if len(v)!=16{t.Fatalf("wrong binding count: %d",len(v))}
 if !strings.Contains(s.Text(),"@"){t.Fatal("player not visible")}
 for y:=0;y<Height;y++{
  row:=v["row"+string(rune('0'+y))]
  if len(row)!=ViewWidth{t.Fatalf("viewport %d has %d cells",y,len(row))}
 }
}
func TestCoinScoringAndNoDuplication(t *testing.T){
 s:=New()
 for i:=0;i<5;i++{if err:=s.Step("right");err!=nil{t.Fatal(err)}}
 if s.Score!=100||len(s.Collected)!=1{t.Fatalf("expected first coin: %+v",s)}
 _=s.Step("left");_=s.Step("right")
 if s.Score!=100{t.Fatal("repeated coin paid twice")}
}
func TestJumpAndLanding(t *testing.T){
 s:=New()
 if err:=s.Step("jump-right");err!=nil{t.Fatal(err)}
 if s.Y>=Height-2||s.X!=3{t.Fatalf("jump failed: %+v",s)}
 for i:=0;i<8;i++{_ =s.Step("wait")}
 if s.Y!=Height-2||s.Velocity!=0{t.Fatalf("landing failed: %+v",s)}
}
func TestPitAndReset(t *testing.T){
 s:=New();s.X=14
 _=s.Step("right")
 if s.Lives!=2||s.X!=2{t.Fatalf("expected pit respawn: %+v",s)}
 s.Lives=1;s.X=14
 _=s.Step("right")
 if !s.Over||s.Lives!=0{t.Fatalf("expected game over: %+v",s)}
 _=s.Step("new")
 if s.Over||s.Lives!=3||s.Score!=0{t.Fatalf("reset failed: %+v",s)}
}
func TestEnemyAndLevelCompletion(t *testing.T){
 s:=New();s.X=10;_=s.Step("right")
 if s.Lives!=2{t.Fatalf("enemy not lethal: %+v",s)}
 s=New();s.X=66;_=s.Step("right")
 if s.Level!=2||s.Score!=500||s.X!=2{t.Fatalf("level 1 not finished: %+v",s)}
 s.Level=3;s.X=89;_=s.Step("right")
 if !s.Won||!s.Over{t.Fatalf("game not won: %+v",s)}
}
func TestInvalidCommandsAndStateBoundaries(t *testing.T){
 s:=New()
 if err:=s.Step("inject");err==nil{t.Fatal("invalid command accepted")}
 if s.Turns!=0{t.Fatal("invalid command changed state")}
 _=s.Step("play")
 if s.Turns!=0{t.Fatal("show must not advance physics")}
 s.Level=999
 if s.Valid(){t.Fatal("invalid level accepted")}
}

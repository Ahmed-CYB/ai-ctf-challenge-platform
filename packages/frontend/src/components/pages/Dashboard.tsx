import { Card } from '../ui/card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Trophy, Target, Flame, TrendingUp, Clock, Users } from 'lucide-react';
import { currentUser, userStats, mockChallenges } from '../../data/mockData';
import { Progress } from '../ui/progress';

export function Dashboard() {
  const recentChallenges = mockChallenges.filter(c => c.isPublished).slice(0, 4);
  const recommendedChallenges = mockChallenges.filter(c => c.isPublished && c.difficulty === 'Intermediate').slice(0, 3);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1>Welcome back, {currentUser.username}!</h1>
        <p className="text-muted-foreground">Here's your cybersecurity learning progress</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground">Challenges Solved</p>
              <h2>{userStats.totalSolved}</h2>
            </div>
            <div className="bg-primary/10 p-3 rounded-lg">
              <Trophy className="w-6 h-6 text-primary" />
            </div>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground">Total Points</p>
              <h2>{userStats.totalPoints}</h2>
            </div>
            <div className="bg-chart-2/10 p-3 rounded-lg">
              <Target className="w-6 h-6 text-chart-2" />
            </div>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground">Current Streak</p>
              <h2>{userStats.currentStreak} days</h2>
            </div>
            <div className="bg-chart-4/10 p-3 rounded-lg">
              <Flame className="w-6 h-6 text-chart-4" />
            </div>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground">Global Rank</p>
              <h2>#{currentUser.rank}</h2>
            </div>
            <div className="bg-chart-1/10 p-3 rounded-lg">
              <TrendingUp className="w-6 h-6 text-chart-1" />
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Category Progress */}
        <Card className="p-6 lg:col-span-2">
          <h3 className="mb-4">Category Progress</h3>
          <div className="space-y-4">
            {userStats.categoriesBreakdown.map((cat) => (
              <div key={cat.category}>
                <div className="flex items-center justify-between mb-2">
                  <p className="font-medium">{cat.category}</p>
                  <p className="text-muted-foreground">{cat.solved}/{cat.total}</p>
                </div>
                <Progress value={(cat.solved / cat.total) * 100} />
              </div>
            ))}
          </div>
        </Card>

        {/* Quick Stats */}
        <Card className="p-6">
          <h3 className="mb-4">Quick Stats</h3>
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="bg-muted p-2 rounded">
                <Clock className="w-4 h-4" />
              </div>
              <div>
                <p className="text-muted-foreground">Longest Streak</p>
                <p className="font-medium">{userStats.longestStreak} days</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="bg-muted p-2 rounded">
                <Trophy className="w-4 h-4" />
              </div>
              <div>
                <p className="text-muted-foreground">Challenges Created</p>
                <p className="font-medium">{currentUser.challengesCreated}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="bg-muted p-2 rounded">
                <Users className="w-4 h-4" />
              </div>
              <div>
                <p className="text-muted-foreground">Skill Level</p>
                <p className="font-medium">{currentUser.level}</p>
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* Recent Challenges */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h3>Recent Challenges</h3>
          <Button variant="ghost" size="sm">View All</Button>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {recentChallenges.map((challenge) => (
            <Card key={challenge.id} className="p-4 hover:border-primary transition-colors cursor-pointer">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <h4>{challenge.title}</h4>
                  <p className="text-muted-foreground line-clamp-2 mt-1">{challenge.description}</p>
                </div>
              </div>
              <div className="flex items-center gap-2 mt-3">
                <Badge variant="secondary">{challenge.category}</Badge>
                <Badge variant={
                  challenge.difficulty === 'Beginner' ? 'default' :
                  challenge.difficulty === 'Intermediate' ? 'secondary' : 'destructive'
                }>
                  {challenge.difficulty}
                </Badge>
                <div className="flex-1" />
                <p className="text-muted-foreground">{challenge.points} pts</p>
              </div>
            </Card>
          ))}
        </div>
      </Card>

      {/* Recommended */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h3>Recommended for You</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {recommendedChallenges.map((challenge) => (
            <Card key={challenge.id} className="p-4 hover:border-primary transition-colors cursor-pointer">
              <Badge variant="secondary" className="mb-2">{challenge.category}</Badge>
              <h4 className="mb-1">{challenge.title}</h4>
              <p className="text-muted-foreground line-clamp-2 mb-3">{challenge.description}</p>
              <div className="flex items-center justify-between">
                <p className="text-muted-foreground">{challenge.solves} solves</p>
                <p className="font-medium text-primary">{challenge.points} pts</p>
              </div>
            </Card>
          ))}
        </div>
      </Card>
    </div>
  );
}

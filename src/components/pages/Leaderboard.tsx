import { Card } from '../ui/card';
import { Badge } from '../ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '../ui/avatar';
import { Trophy, Medal, Award } from 'lucide-react';
import { mockUsers, currentUser } from '../../data/mockData';

export function Leaderboard() {
  const sortedUsers = [...mockUsers].sort((a, b) => a.rank - b.rank);

  const getRankIcon = (rank: number) => {
    if (rank === 1) return <Trophy className="w-5 h-5 text-yellow-500" />;
    if (rank === 2) return <Medal className="w-5 h-5 text-gray-400" />;
    if (rank === 3) return <Award className="w-5 h-5 text-orange-600" />;
    return null;
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1>Leaderboard</h1>
        <p className="text-muted-foreground">Top performers in the CTF platform</p>
      </div>

      {/* Top 3 Podium */}
      <div className="grid grid-cols-3 gap-4 mb-6 items-end">
        {/* Rank 2 - Left - Medium height */}
        {sortedUsers[1] && (
          <Card 
            className={`p-6 text-center flex flex-col items-center gap-3 ${
              sortedUsers[1].id === currentUser.id ? 'border-primary' : ''
            }`}
          >
            <div className="flex justify-center">
              {getRankIcon(2)}
            </div>
            <Avatar className="w-16 h-16">
              <AvatarImage src={sortedUsers[1].avatar} />
              <AvatarFallback>{sortedUsers[1].username[0].toUpperCase()}</AvatarFallback>
            </Avatar>
            <div>
              <h4 className="mb-1 truncate">{sortedUsers[1].username}</h4>
              <p className="text-muted-foreground">{sortedUsers[1].points} points</p>
            </div>
            <Badge variant="secondary">{sortedUsers[1].level}</Badge>
          </Card>
        )}

        {/* Rank 1 - Center - Tallest */}
        {sortedUsers[0] && (
          <Card 
            className={`p-6 text-center flex flex-col items-center gap-3 ${
              sortedUsers[0].id === currentUser.id ? 'border-primary' : ''
            }`}
          >
            <div className="flex justify-center">
              {getRankIcon(1)}
            </div>
            <Avatar className="w-20 h-20">
              <AvatarImage src={sortedUsers[0].avatar} />
              <AvatarFallback>{sortedUsers[0].username[0].toUpperCase()}</AvatarFallback>
            </Avatar>
            <div>
              <h4 className="mb-1 truncate">{sortedUsers[0].username}</h4>
              <p className="text-muted-foreground">{sortedUsers[0].points} points</p>
            </div>
            <Badge variant="secondary">{sortedUsers[0].level}</Badge>
          </Card>
        )}

        {/* Rank 3 - Right - Shortest */}
        {sortedUsers[2] && (
          <Card 
            className={`p-6 text-center flex flex-col items-center gap-3 ${
              sortedUsers[2].id === currentUser.id ? 'border-primary' : ''
            }`}
          >
            <div className="flex justify-center">
              {getRankIcon(3)}
            </div>
            <Avatar className="w-14 h-14">
              <AvatarImage src={sortedUsers[2].avatar} />
              <AvatarFallback>{sortedUsers[2].username[0].toUpperCase()}</AvatarFallback>
            </Avatar>
            <div>
              <h4 className="mb-1 truncate">{sortedUsers[2].username}</h4>
              <p className="text-muted-foreground">{sortedUsers[2].points} points</p>
            </div>
            <Badge variant="secondary">{sortedUsers[2].level}</Badge>
          </Card>
        )}
      </div>

      {/* Full Rankings */}
      <Card>
        <div className="divide-y divide-border">
          {sortedUsers.map((user) => (
            <div
              key={user.id}
              className={`p-4 flex items-center gap-4 hover:bg-muted/50 transition-colors ${
                user.id === currentUser.id ? 'bg-primary/5' : ''
              }`}
            >
              <div className="w-12 text-center">
                {getRankIcon(user.rank) || (
                  <p className="font-medium">#{user.rank}</p>
                )}
              </div>

              <Avatar className="w-12 h-12">
                <AvatarImage src={user.avatar} />
                <AvatarFallback>{user.username[0].toUpperCase()}</AvatarFallback>
              </Avatar>

              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <h4>{user.username}</h4>
                  {user.id === currentUser.id && (
                    <Badge variant="default">You</Badge>
                  )}
                </div>
                <p className="text-muted-foreground">{user.level}</p>
              </div>

              <div className="text-right">
                <p className="font-medium">{user.points} pts</p>
                <p className="text-muted-foreground">{user.challengesSolved} solved</p>
              </div>

              <div className="text-right">
                <p className="text-muted-foreground">{user.challengesCreated} created</p>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

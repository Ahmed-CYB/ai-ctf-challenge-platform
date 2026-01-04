import { useState, useEffect } from 'react';
import { Card } from '../ui/card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs';
import { Avatar, AvatarFallback, AvatarImage } from '../ui/avatar';
import { Trophy, Target, Flame, Calendar, Edit, ExternalLink, Trash2 } from 'lucide-react';
import { mockChallenges, savedChallenges } from '../../data/mockData';
import { getCurrentUser } from '../../services/auth';
import type { User } from '../../services/auth';
import { AnimalAvatar } from '../AnimalAvatar';

interface ProfileProps {
  onEditProfile: () => void;
}

export function Profile({ onEditProfile }: ProfileProps) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadUser = async () => {
      setLoading(true);
      // Force refresh to get latest data from server
      const currentUser = await getCurrentUser(true);
      setUser(currentUser);
      setLoading(false);
    };
    loadUser();
  }, []); // This will re-run when the component remounts (key changes)

  // For now, use a static user ID for filtering. In production, this would use the actual user ID
  const userId = user?.id || 'user-1';
  const publishedChallenges = mockChallenges.filter(c => c.isPublished);
  const draftChallenges = mockChallenges.filter(c => !c.isPublished);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Profile Header */}
      <Card className="p-6">
        <div className="flex items-start gap-6">
          {/* Avatar Display */}
          <AnimalAvatar animalId={user?.avatar || 'lion'} size={96} />
          
          <div className="flex-1">
            <div className="flex items-start justify-between">
              <div>
                <h1>{user?.name || 'Loading...'}</h1>
                <p className="text-muted-foreground">@{user?.username || 'username'}</p>
                {user?.role && (
                  <p className="text-muted-foreground">{user.role}</p>
                )}
                <p className="text-muted-foreground">{user?.email || ''}</p>
                <p className="text-muted-foreground mt-2">{user?.bio || 'No bio yet. Click Edit Profile to add one!'}</p>
              </div>
              <Button size="sm" variant="outline" onClick={onEditProfile}>
                <Edit className="w-4 h-4 mr-2" />
                Edit Profile
              </Button>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
              <div className="flex items-center gap-3">
                <div className="bg-primary/10 p-2 rounded">
                  <Trophy className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <p className="text-muted-foreground">Rank</p>
                  <p className="font-medium">#12</p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <div className="bg-chart-2/10 p-2 rounded">
                  <Target className="w-5 h-5 text-chart-2" />
                </div>
                <div>
                  <p className="text-muted-foreground">Points</p>
                  <p className="font-medium">2450</p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <div className="bg-chart-3/10 p-2 rounded">
                  <Trophy className="w-5 h-5 text-chart-3" />
                </div>
                <div>
                  <p className="text-muted-foreground">Solved</p>
                  <p className="font-medium">34</p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <div className="bg-chart-4/10 p-2 rounded">
                  <Flame className="w-5 h-5 text-chart-4" />
                </div>
                <div>
                  <p className="text-muted-foreground">Current Streak</p>
                  <p className="font-medium">7 days</p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <div className="bg-chart-1/10 p-2 rounded">
                  <Calendar className="w-5 h-5 text-chart-1" />
                </div>
                <div>
                  <p className="text-muted-foreground">Created</p>
                  <p className="font-medium">8</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* Challenges Tabs */}
      <Tabs defaultValue="published" className="w-full">
        <TabsList>
          <TabsTrigger value="published">Published Challenges ({publishedChallenges.length})</TabsTrigger>
          <TabsTrigger value="drafts">Drafts ({draftChallenges.length})</TabsTrigger>
          <TabsTrigger value="saved">Saved Challenges ({savedChallenges.length})</TabsTrigger>
        </TabsList>

        {/* Published Challenges */}
        <TabsContent value="published" className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {publishedChallenges.map((challenge) => (
              <Card key={challenge.id} className="p-4">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <h3>{challenge.title}</h3>
                    <p className="text-muted-foreground line-clamp-2 mt-1">{challenge.description}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2 mb-3">
                  <Badge variant="secondary">{challenge.category}</Badge>
                  <Badge variant={
                    challenge.difficulty === 'Beginner' ? 'default' :
                    challenge.difficulty === 'Intermediate' ? 'secondary' : 'destructive'
                  }>
                    {challenge.difficulty}
                  </Badge>
                </div>

                <div className="flex items-center justify-between text-muted-foreground mb-3">
                  <p>{challenge.solves} solves</p>
                  <p>{challenge.attempts} attempts</p>
                  <p>{challenge.points} points</p>
                </div>

                <div className="flex items-center gap-2">
                  <Button size="sm" variant="outline" className="flex-1">
                    <ExternalLink className="w-4 h-4 mr-2" />
                    View Challenge
                  </Button>
                  <Button size="sm" variant="outline">
                    <Edit className="w-4 h-4" />
                  </Button>
                  <Button size="sm" variant="outline">
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Draft Challenges */}
        <TabsContent value="drafts" className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {draftChallenges.map((challenge) => (
              <Card key={challenge.id} className="p-4 border-dashed">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <h3>{challenge.title}</h3>
                      <Badge variant="outline">Draft</Badge>
                    </div>
                    <p className="text-muted-foreground line-clamp-2">{challenge.description}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2 mb-3">
                  <Badge variant="secondary">{challenge.category}</Badge>
                  <Badge variant={
                    challenge.difficulty === 'Beginner' ? 'default' :
                    challenge.difficulty === 'Intermediate' ? 'secondary' : 'destructive'
                  }>
                    {challenge.difficulty}
                  </Badge>
                </div>

                <div className="flex items-center gap-2">
                  <Button size="sm" className="flex-1">
                    Publish Challenge
                  </Button>
                  <Button size="sm" variant="outline">
                    <Edit className="w-4 h-4" />
                  </Button>
                  <Button size="sm" variant="outline">
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Saved Challenges */}
        <TabsContent value="saved" className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {savedChallenges.map((challenge) => (
              <Card key={challenge.id} className="p-4">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <h3>{challenge.title}</h3>
                    <p className="text-muted-foreground line-clamp-2 mt-1">{challenge.description}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2 mb-3">
                  <Avatar className="w-6 h-6">
                    <AvatarImage src={challenge.author.avatar} />
                    <AvatarFallback>{challenge.author.username[0].toUpperCase()}</AvatarFallback>
                  </Avatar>
                  <p className="text-muted-foreground">by {challenge.author.username}</p>
                </div>

                <div className="flex items-center gap-2 mb-3">
                  <Badge variant="secondary">{challenge.category}</Badge>
                  <Badge variant={
                    challenge.difficulty === 'Beginner' ? 'default' :
                    challenge.difficulty === 'Intermediate' ? 'secondary' : 'destructive'
                  }>
                    {challenge.difficulty}
                  </Badge>
                </div>

                <div className="flex items-center justify-between text-muted-foreground mb-3">
                  <p>{challenge.solves} solves</p>
                  <p>{challenge.points} points</p>
                </div>

                <div className="flex items-center gap-2">
                  <Button size="sm" variant="outline" className="flex-1">
                    <ExternalLink className="w-4 h-4 mr-2" />
                    Start Challenge
                  </Button>
                  <Button size="sm" variant="outline">
                    Remove
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

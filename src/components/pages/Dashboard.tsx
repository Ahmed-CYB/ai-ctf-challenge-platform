import { useState } from 'react';
import { Card } from '../ui/card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Sparkles, Package, CheckCircle2, FileText, Plus, ExternalLink } from 'lucide-react';
import { currentUser, mockChallenges } from '../../data/mockData';
import { Page } from '../../App';

interface DashboardProps {
  onPageChange?: (page: Page) => void;
}

export function Dashboard({ onPageChange }: DashboardProps) {
  const [userChallenges] = useState(
    mockChallenges.filter(c => c.author.id === currentUser.id)
  );

  const publishedChallenges = userChallenges.filter(c => c.isPublished);
  const draftChallenges = userChallenges.filter(c => !c.isPublished);
  const recentChallenges = userChallenges
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, 6);

  const handleGenerateChallenge = () => {
    if (onPageChange) {
      onPageChange('generate');
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1>Welcome back, {currentUser.username}!</h1>
          <p className="text-muted-foreground">Manage your AI-generated CTF challenges</p>
        </div>
        <Button onClick={handleGenerateChallenge} size="lg" className="gap-2">
          <Plus className="w-4 h-4" />
          Generate New Challenge
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground">Total Created</p>
              <h2>{userChallenges.length}</h2>
            </div>
            <div className="bg-primary/10 p-3 rounded-lg">
              <Sparkles className="w-6 h-6 text-primary" />
            </div>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground">Published</p>
              <h2>{publishedChallenges.length}</h2>
            </div>
            <div className="bg-green-500/10 p-3 rounded-lg">
              <CheckCircle2 className="w-6 h-6 text-green-500" />
            </div>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground">Drafts</p>
              <h2>{draftChallenges.length}</h2>
            </div>
            <div className="bg-orange-500/10 p-3 rounded-lg">
              <FileText className="w-6 h-6 text-orange-500" />
            </div>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted-foreground">Total Solves</p>
              <h2>{publishedChallenges.reduce((sum, c) => sum + (c.solves || 0), 0)}</h2>
            </div>
            <div className="bg-blue-500/10 p-3 rounded-lg">
              <Package className="w-6 h-6 text-blue-500" />
            </div>
          </div>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card className="p-6">
        <h3 className="mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Button
            variant="outline"
            className="h-auto p-4 flex flex-col items-start gap-2"
            onClick={handleGenerateChallenge}
          >
            <div className="flex items-center gap-2 w-full">
              <Sparkles className="w-5 h-5 text-primary" />
              <span className="font-semibold">Generate Challenge</span>
            </div>
            <p className="text-sm text-muted-foreground text-left">
              Use AI to create a new CTF challenge
            </p>
          </Button>
          <Button
            variant="outline"
            className="h-auto p-4 flex flex-col items-start gap-2"
            onClick={() => onPageChange?.('generate')}
          >
            <div className="flex items-center gap-2 w-full">
              <Package className="w-5 h-5 text-primary" />
              <span className="font-semibold">View All Challenges</span>
            </div>
            <p className="text-sm text-muted-foreground text-left">
              Browse and manage all your challenges
            </p>
          </Button>
          <Button
            variant="outline"
            className="h-auto p-4 flex flex-col items-start gap-2"
            onClick={() => onPageChange?.('profile')}
          >
            <div className="flex items-center gap-2 w-full">
              <FileText className="w-5 h-5 text-primary" />
              <span className="font-semibold">View Profile</span>
            </div>
            <p className="text-sm text-muted-foreground text-left">
              Check your profile and settings
            </p>
          </Button>
        </div>
      </Card>

      {/* My Challenges */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h3>My Challenges</h3>
          <Button variant="ghost" size="sm" onClick={handleGenerateChallenge}>
            <Plus className="w-4 h-4 mr-2" />
            Create New
          </Button>
        </div>
        {recentChallenges.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {recentChallenges.map((challenge) => (
              <Card key={challenge.id} className="p-4 hover:border-primary transition-colors">
                <div className="flex items-start justify-between mb-3">
                  <Badge variant="secondary">{challenge.category}</Badge>
                  <Badge variant={challenge.isPublished ? 'default' : 'outline'}>
                    {challenge.isPublished ? 'Published' : 'Draft'}
                  </Badge>
                </div>
                <h4 className="mb-2">{challenge.title}</h4>
                <p className="text-muted-foreground line-clamp-2 mb-3 text-sm">
                  {challenge.description}
                </p>
                <div className="flex items-center justify-between mb-3">
                  <Badge variant={
                    challenge.difficulty === 'Beginner' ? 'default' :
                    challenge.difficulty === 'Intermediate' ? 'secondary' : 'destructive'
                  }>
                    {challenge.difficulty}
                  </Badge>
                  {challenge.isPublished && (
                    <div className="flex items-center gap-1 text-muted-foreground text-sm">
                      <Package className="w-3 h-3" />
                      <span>{challenge.solves || 0} solves</span>
                    </div>
                  )}
                </div>
                {challenge.isPublished && challenge.targetUrl && (
                  <Button variant="outline" size="sm" className="w-full" asChild>
                    <a href={challenge.targetUrl} target="_blank" rel="noopener noreferrer">
                      <ExternalLink className="w-4 h-4 mr-2" />
                      Access Challenge
                    </a>
                  </Button>
                )}
                {!challenge.isPublished && (
                  <Button variant="outline" size="sm" className="w-full">
                    Continue Editing
                  </Button>
                )}
              </Card>
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <Sparkles className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <h4 className="mb-2">No challenges yet</h4>
            <p className="text-muted-foreground mb-4">
              Start creating your first AI-generated CTF challenge
            </p>
            <Button onClick={handleGenerateChallenge}>
              <Plus className="w-4 h-4 mr-2" />
              Generate Challenge
            </Button>
          </div>
        )}
      </Card>
    </div>
  );
}

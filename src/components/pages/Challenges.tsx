import { useState } from 'react';
import { Card } from '../ui/card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { Avatar, AvatarFallback, AvatarImage } from '../ui/avatar';
import { Search, Filter, ExternalLink, Bookmark, BookmarkCheck } from 'lucide-react';
import { mockChallenges } from '../../data/mockData';

export function Challenges() {
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [difficultyFilter, setDifficultyFilter] = useState<string>('all');
  const [savedChallengeIds, setSavedChallengeIds] = useState<string[]>(['ch-4', 'ch-6', 'ch-7']);

  const publishedChallenges = mockChallenges.filter(c => c.isPublished);

  const filteredChallenges = publishedChallenges.filter(challenge => {
    const matchesSearch = challenge.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          challenge.description.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = categoryFilter === 'all' || challenge.category === categoryFilter;
    const matchesDifficulty = difficultyFilter === 'all' || challenge.difficulty === difficultyFilter;
    
    return matchesSearch && matchesCategory && matchesDifficulty;
  });

  const categories = ['all', ...new Set(publishedChallenges.map(c => c.category))];
  const difficulties = ['all', 'Beginner', 'Intermediate', 'Advanced'];

  const toggleSave = (challengeId: string) => {
    setSavedChallengeIds(prev => 
      prev.includes(challengeId) 
        ? prev.filter(id => id !== challengeId)
        : [...prev, challengeId]
    );
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1>Explore Challenges</h1>
        <p className="text-muted-foreground">Discover and solve CTF challenges from the community</p>
      </div>

      {/* Filters */}
      <Card className="p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="md:col-span-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search challenges..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
          </div>

          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger>
              <Filter className="w-4 h-4 mr-2" />
              <SelectValue placeholder="Category" />
            </SelectTrigger>
            <SelectContent>
              {categories.map((cat) => (
                <SelectItem key={cat} value={cat}>
                  {cat === 'all' ? 'All Categories' : cat}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={difficultyFilter} onValueChange={setDifficultyFilter}>
            <SelectTrigger>
              <SelectValue placeholder="Difficulty" />
            </SelectTrigger>
            <SelectContent>
              {difficulties.map((diff) => (
                <SelectItem key={diff} value={diff}>
                  {diff === 'all' ? 'All Difficulties' : diff}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </Card>

      {/* Results Count */}
      <div className="flex items-center justify-between">
        <p className="text-muted-foreground">
          Showing {filteredChallenges.length} {filteredChallenges.length === 1 ? 'challenge' : 'challenges'}
        </p>
      </div>

      {/* Challenge Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredChallenges.map((challenge) => {
          const isSaved = savedChallengeIds.includes(challenge.id);
          
          return (
            <Card key={challenge.id} className="p-4 hover:border-primary transition-colors">
              <div className="flex items-start justify-between mb-3">
                <Badge variant="secondary">{challenge.category}</Badge>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => toggleSave(challenge.id)}
                  className="h-8 w-8 p-0"
                >
                  {isSaved ? (
                    <BookmarkCheck className="w-4 h-4 text-primary" />
                  ) : (
                    <Bookmark className="w-4 h-4" />
                  )}
                </Button>
              </div>

              <h3 className="mb-2">{challenge.title}</h3>
              <p className="text-muted-foreground line-clamp-3 mb-4">{challenge.description}</p>

              <div className="flex items-center gap-2 mb-3">
                <Avatar className="w-6 h-6">
                  <AvatarImage src={challenge.author.avatar} />
                  <AvatarFallback>{challenge.author.name[0]}</AvatarFallback>
                </Avatar>
                <p className="text-muted-foreground">{challenge.author.name}</p>
              </div>

              <div className="flex items-center gap-2 mb-4">
                <Badge variant={
                  challenge.difficulty === 'Beginner' ? 'default' :
                  challenge.difficulty === 'Intermediate' ? 'secondary' : 'destructive'
                }>
                  {challenge.difficulty}
                </Badge>
                <div className="flex-1" />
                <p className="text-muted-foreground">{challenge.solves} solves</p>
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-border">
                <p className="font-medium text-primary">{challenge.points} points</p>
                <Button size="sm" variant="outline">
                  <ExternalLink className="w-4 h-4 mr-2" />
                  Start
                </Button>
              </div>
            </Card>
          );
        })}
      </div>

      {filteredChallenges.length === 0 && (
        <Card className="p-12 text-center">
          <p className="text-muted-foreground">No challenges found matching your filters</p>
          <Button
            variant="outline"
            className="mt-4"
            onClick={() => {
              setSearchQuery('');
              setCategoryFilter('all');
              setDifficultyFilter('all');
            }}
          >
            Clear Filters
          </Button>
        </Card>
      )}
    </div>
  );
}

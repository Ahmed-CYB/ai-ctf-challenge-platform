import { useState, useEffect } from 'react';
import { Card } from '../ui/card';
import { Button } from '../ui/button';
import { Sparkles, Package, FileText } from 'lucide-react';
import { getCurrentUser } from '../../services/auth';
import type { User } from '../../services/auth';
import { Page } from '../../App';

interface DashboardProps {
  onPageChange?: (page: Page) => void;
}

export function Dashboard({ onPageChange }: DashboardProps) {
  const [currentUser, setCurrentUser] = useState<User | null>(null);

  useEffect(() => {
    const loadUser = async () => {
      const user = await getCurrentUser(true);
      setCurrentUser(user);
    };
    loadUser();
  }, []);

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
          <h1>Welcome back, {currentUser?.username || 'user'}!</h1>
          <p className="text-muted-foreground">Manage your AI-generated CTF challenges</p>
        </div>
      </div>

      {/* Quick Actions */}
      <Card className="p-6">
        <h3 className="mb-4">Quick Actions</h3>
        <div className="flex flex-col gap-4">
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
              Browse challenge using chat
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
    </div>
  );
}

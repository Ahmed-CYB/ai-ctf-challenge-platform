import { useState, useEffect } from 'react';
import { Card } from '../ui/card';
import { Button } from '../ui/button';
import { Edit } from 'lucide-react';
import { getCurrentUser } from '../../services/auth';
import type { User } from '../../services/auth';
import { AnimalAvatar } from '../AnimalAvatar';

interface ProfileProps {
  onEditProfile: () => void;
}

export function Profile({ onEditProfile }: ProfileProps) {
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    const loadUser = async () => {
      // Force refresh to get latest data from server
      const currentUser = await getCurrentUser(true);
      setUser(currentUser);
    };
    loadUser();
  }, []); // This will re-run when the component remounts (key changes)


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
          </div>
        </div>
      </Card>
    </div>
  );
}

import { useState, useEffect } from 'react';
import { Home, Sparkles, User, Terminal, LogOut } from 'lucide-react';
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarHeader,
  SidebarFooter,
} from './ui/sidebar';
import { getCurrentUser } from '../services/auth';
import type { User as UserType } from '../services/auth';
import { Avatar, AvatarFallback, AvatarImage } from './ui/avatar';
import { Button } from './ui/button';
import { Separator } from './ui/separator';
import { Page } from '../App';
import { AnimalAvatar } from './AnimalAvatar';

interface AppSidebarProps {
  currentPage: Page;
  onPageChange: (page: Page) => void;
  onLogout: () => void;
  refreshKey?: number;
}

export function AppSidebar({ currentPage, onPageChange, onLogout, refreshKey }: AppSidebarProps) {
  const [user, setUser] = useState<UserType | null>(null);

  useEffect(() => {
    const loadUser = async () => {
      // Force refresh to get latest data from server
      const currentUser = await getCurrentUser(true);
      setUser(currentUser);
    };
    loadUser();
  }, [refreshKey]); // Refresh when refreshKey changes

  const menuItems = [
    { id: 'dashboard' as Page, label: 'Dashboard', icon: Home },
    { id: 'generate' as Page, label: 'Generate Challenge', icon: Sparkles },
    { id: 'profile' as Page, label: 'Profile', icon: User },
  ];

  return (
    <Sidebar>
      <SidebarHeader>
        <div className="flex items-center gap-2 px-4 py-3">
          <div className="bg-primary text-primary-foreground p-2 rounded-lg glow-primary-sm">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <p className="font-medium terminal-text">CTF Platform</p>
            <p className="text-primary text-xs">AI-Powered</p>
          </div>
        </div>
      </SidebarHeader>
      
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Navigation</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {menuItems.map((item) => (
                <SidebarMenuItem key={item.id}>
                  <SidebarMenuButton
                    onClick={() => onPageChange(item.id)}
                    isActive={currentPage === item.id}
                  >
                    <item.icon className="w-4 h-4" />
                    <span>{item.label}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter>
        <div className="p-4 space-y-3">
          <Separator />
          
          <div className="flex items-center gap-3">
            {/* Avatar Display */}
            <AnimalAvatar animalId={user?.avatar || 'lion'} size={40} />
            <div className="flex-1 min-w-0">
              <p className="font-medium truncate">{user?.username || 'Loading...'}</p>
              <p className="text-muted-foreground truncate">2450 pts</p>
            </div>
          </div>

          <Button 
            variant="outline" 
            size="sm" 
            className="w-full justify-start"
            onClick={onLogout}
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </Button>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}

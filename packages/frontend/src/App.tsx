import { useState, useEffect } from 'react';
import { Toaster } from './components/ui/sonner';
import { AppSidebar } from './components/AppSidebar';
import { SidebarProvider } from './components/ui/sidebar';
import { Dashboard } from './components/pages/Dashboard';
import { Profile } from './components/pages/Profile';
import { EditProfile } from './components/pages/EditProfile';
import { GenerateChallenge } from './components/pages/GenerateChallenge';
import { Login } from './components/pages/Login';
import { SignUp } from './components/pages/SignUp';
import { isAuthenticated, logout } from './services/auth';
import { testConnection } from './services/database';
// Database will be accessed via backend API

export type Page = 'dashboard' | 'generate' | 'profile' | 'edit-profile';
export type AuthPage = 'login' | 'signup';

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState<boolean | null>(null); // null = checking, false = not logged in, true = logged in
  const [authPage, setAuthPage] = useState<AuthPage>('login');
  const [currentPage, setCurrentPage] = useState<Page>('dashboard');
  const [profileRefreshKey, setProfileRefreshKey] = useState(0);

  // Check authentication and backend API on mount
  useEffect(() => {
    const checkAuth = async () => {
      const authenticated = await isAuthenticated();
      setIsLoggedIn(authenticated);
    };
    
    const checkBackend = async () => {
      const connected = await testConnection();
      if (connected) {
        console.log('✅ Backend API is ready!');
      } else {
        console.error('❌ Backend API connection failed. Make sure backend server is running on port 3002.');
      }
    };
    
    // Check auth immediately
    checkAuth();
    checkBackend();
  }, []);

  const handleLoginSuccess = () => {
    setIsLoggedIn(true);
  };

  const handleSignUpSuccess = () => {
    setAuthPage('login');
  };

  const handleLogout = async () => {
    await logout();
    setIsLoggedIn(false);
    setCurrentPage('dashboard');
    setAuthPage('login');
  };

  const handleProfileSaved = () => {
    // Increment key to force Profile component to refresh
    setProfileRefreshKey(prev => prev + 1);
    setCurrentPage('profile');
  };

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard onPageChange={setCurrentPage} />;
      case 'generate':
        return <GenerateChallenge />;
      case 'profile':
        return <Profile key={profileRefreshKey} onEditProfile={() => setCurrentPage('edit-profile')} />;
      case 'edit-profile':
        return <EditProfile onBack={() => setCurrentPage('profile')} onSaved={handleProfileSaved} />;
      default:
        return <Dashboard onPageChange={setCurrentPage} />;
    }
  };

  // Show loading state while checking authentication
  if (isLoggedIn === null) {
    return (
      <div className="dark min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  // Show login or signup page if not authenticated
  if (!isLoggedIn) {
    return (
      <div className="dark min-h-screen">
        {authPage === 'login' ? (
          <Login
            onLoginSuccess={handleLoginSuccess}
            onSwitchToSignUp={() => setAuthPage('signup')}
          />
        ) : (
          <SignUp
            onSignUpSuccess={handleSignUpSuccess}
            onSwitchToLogin={() => setAuthPage('login')}
          />
        )}
        <Toaster />
      </div>
    );
  }

  // Show main app if authenticated
  return (
    <div className="dark">
      <SidebarProvider>
        <div className="flex min-h-screen w-full bg-background">
          <AppSidebar 
            currentPage={currentPage} 
            onPageChange={setCurrentPage}
            onLogout={handleLogout}
            refreshKey={profileRefreshKey}
          />
          <main className="flex-1 overflow-auto">
            {renderPage()}
          </main>
        </div>
        <Toaster />
      </SidebarProvider>
    </div>
  );
}

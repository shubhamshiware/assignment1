import { useEffect, useState } from 'react';
import { useAuth } from '@getmocha/users-service/react';

interface User {
  id: string;
  email: string;
  name?: string;
}

interface ExtendedAuthContext {
  user: User | null;
  isPending: boolean;
  logout: () => Promise<void>;
  redirectToLogin: () => void;
}

export function useExtendedAuth(): ExtendedAuthContext {
  const mochaAuth = useAuth();
  const [emailUser, setEmailUser] = useState<User | null>(null);
  const [emailIsPending, setEmailIsPending] = useState(true);

  useEffect(() => {
    const checkEmailAuth = async () => {
      try {
        const response = await fetch('/api/users/me', {
          credentials: 'include',
        });
        if (response.ok) {
          const userData = await response.json();
          const user: User = {
            id: userData.id,
            email: userData.email,
            name: userData.name || `${userData.first_name || ''} ${userData.last_name || ''}`.trim(),
          };
          setEmailUser(user);
        }
      } catch (error) {
        console.error('Failed to check email auth:', error);
      } finally {
        setEmailIsPending(false);
      }
    };

    checkEmailAuth();
  }, []);

  const user = mochaAuth.user || emailUser;
  const isPending = mochaAuth.isPending || emailIsPending;

  return {
    user,
    isPending,
    logout: mochaAuth.logout,
    redirectToLogin: mochaAuth.redirectToLogin,
  };
}

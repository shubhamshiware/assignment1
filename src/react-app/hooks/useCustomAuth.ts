import { useState, useEffect, useCallback } from 'react';

interface User {
  id: string;
  email: string;
  name?: string;
}

export function useCustomAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [isPending, setIsPending] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await fetch('/api/users/me', {
          credentials: 'include',
        });
        if (response.ok) {
          const userData = await response.json();
          setUser({
            id: userData.id,
            email: userData.email,
            name: userData.name || `${userData.first_name || ''} ${userData.last_name || ''}`.trim(),
          });
        } else {
          setUser(null);
        }
      } catch (error) {
        console.error('Failed to check auth:', error);
        setUser(null);
      } finally {
        setIsPending(false);
      }
    };

    checkAuth();
  }, []);

  const logout = useCallback(async () => {
    try {
      await fetch('/api/logout', { 
        method: 'GET',
        credentials: 'include',
      });
      setUser(null);
    } catch (error) {
      console.error('Logout failed:', error);
    }
  }, []);

  const redirectToLogin = useCallback(() => {
    window.location.href = '/login';
  }, []);

  return { user, isPending, logout, redirectToLogin };
}

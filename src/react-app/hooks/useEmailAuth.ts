import { useState, useEffect, useCallback } from 'react';

interface User {
  id: string;
  email: string;
  name?: string;
}

export function useEmailAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [isPending, setIsPending] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await fetch('/api/users/me');
        if (response.ok) {
          const userData = await response.json();
          setUser({
            id: userData.id,
            email: userData.email,
            name: userData.name,
          });
        }
      } catch (error) {
        console.error('Failed to check auth:', error);
      } finally {
        setIsPending(false);
      }
    };

    checkAuth();
  }, []);

  const logout = useCallback(async () => {
    try {
      await fetch('/api/logout', { method: 'GET' });
      setUser(null);
    } catch (error) {
      console.error('Logout failed:', error);
    }
  }, []);

  return { user, isPending, logout };
}

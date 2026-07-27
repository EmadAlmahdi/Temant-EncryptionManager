import { useEffect, useState } from "react";

/**
 * Minimal hash-based route state. Deliberately not react-router: this app only ever needs a
 * flat list of top-level package routes (see src/packages/registry.tsx), and hash routing works
 * with zero server configuration wherever the built app ends up being hosted.
 */
export function useHashRoute(defaultRoute: string): [string, (route: string) => void] {
  const readRoute = () => window.location.hash.slice(1) || defaultRoute;
  const [route, setRoute] = useState(readRoute);

  useEffect(() => {
    const onHashChange = () => setRoute(readRoute());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const navigate = (next: string) => {
    window.location.hash = next;
  };

  return [route, navigate];
}

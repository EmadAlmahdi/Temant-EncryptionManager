import { AmbientBackground } from "./components/AmbientBackground";
import { Sidebar } from "./components/Sidebar";
import { useHashRoute } from "./lib/router";
import { packages } from "./packages/registry";

export default function App() {
  const [route, navigate] = useHashRoute(packages[0].id);
  const active = packages.find((pkg) => pkg.id === route) ?? packages[0];
  const ActiveDemo = active.component;

  return (
    <div className="relative flex min-h-screen bg-zinc-50 text-zinc-900 dark:bg-zinc-950 dark:text-zinc-50">
      <AmbientBackground />
      <Sidebar packages={packages} activeId={active.id} onNavigate={navigate} />
      <main className="relative min-w-0 flex-1">
        <ActiveDemo />
      </main>
    </div>
  );
}

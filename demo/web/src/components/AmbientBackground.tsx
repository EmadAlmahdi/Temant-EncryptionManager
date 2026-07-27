/**
 * Fixed, blurred gradient blobs behind the whole app for ambient depth. Purely decorative and
 * non-interactive; static (no motion) so it costs nothing on low-power devices and respects
 * users who'd rather not see movement.
 */
export function AmbientBackground() {
  return (
    <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      <div className="absolute -top-40 -left-32 h-96 w-96 rounded-full bg-indigo-400/25 blur-[110px] dark:bg-indigo-500/15" />
      <div className="absolute top-1/3 -right-32 h-96 w-96 rounded-full bg-fuchsia-400/20 blur-[110px] dark:bg-fuchsia-500/10" />
      <div className="absolute bottom-0 left-1/4 h-80 w-80 rounded-full bg-violet-400/20 blur-[110px] dark:bg-violet-500/10" />
    </div>
  );
}

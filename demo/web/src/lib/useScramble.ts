import { useEffect, useRef, useState } from "react";

const GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=!@#$%^&*";

/**
 * Reveals `text` by animating each character in from random glyphs, left to right — a "decoding"
 * effect that fits an encryption demo better than a generic fade. Re-triggers whenever `text`
 * (or `nonce`) changes. Non-whitespace-preserving: spaces/newlines in the source stay put so the
 * scramble doesn't visually jitter the layout.
 */
export function useScramble(text: string, nonce: number): string {
  const [display, setDisplay] = useState(text);
  const frame = useRef(0);

  useEffect(() => {
    if (!text) {
      setDisplay("");
      return;
    }

    let raf = 0;
    frame.current = 0;
    const totalFrames = Math.min(24, 10 + Math.floor(text.length / 4));

    const step = () => {
      frame.current += 1;
      const revealCount = Math.floor((frame.current / totalFrames) * text.length);

      let next = "";
      for (let i = 0; i < text.length; i++) {
        const char = text[i];
        if (i < revealCount || char === " " || char === "\n") {
          next += char;
        } else {
          next += GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
        }
      }
      setDisplay(next);

      if (frame.current < totalFrames) {
        raf = requestAnimationFrame(step);
      } else {
        setDisplay(text);
      }
    };

    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text, nonce]);

  return display;
}

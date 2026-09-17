import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import EvilEye from "@/components/ui/EvilEye";
import "./landing-cinema.css";

/* -------------------------------------------------------------------------- */
/* Drishti EvilEye Cinematic Entry Animation                                  */
/* -------------------------------------------------------------------------- */
interface EntryAnimationProps {
  children: React.ReactNode;
  forcePlay?: boolean;
  onFinish?: () => void;
}

export function EntryAnimation({ children, forcePlay = false, onFinish }: EntryAnimationProps) {
  const [showSplash, setShowSplash] = useState(true);

  useEffect(() => {
    if (forcePlay) {
      setShowSplash(true);
    }
  }, [forcePlay]);

  const handleDismiss = () => {
    setShowSplash(false);
    onFinish?.();
  };

  // Keyboard shortcut: Press Escape to skip, or click anywhere
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && showSplash) {
        handleDismiss();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [showSplash]);

  // Auto-finish after 1.85s of stunning visual presentation
  useEffect(() => {
    if (!showSplash) return;
    const timer = setTimeout(() => {
      handleDismiss();
    }, 1850);
    return () => clearTimeout(timer);
  }, [showSplash]);

  return (
    <>
      <AnimatePresence>
        {showSplash && (
          <motion.div
            key="evileye-splash"
            className="sleek-entry-curtain cursor-pointer"
            onClick={handleDismiss}
            initial={{ opacity: 1 }}
            exit={{
              opacity: 0,
              scale: 1.04,
              filter: "blur(24px)",
              transition: { duration: 0.7, ease: [0.16, 1, 0.3, 1] },
            }}
          >
            {/* Ambient Background Caustic Lighting */}
            <div className="sleek-ambient-glow" />

            {/* WebGL EvilEye Canvas */}
            <div className="absolute inset-0 z-0 flex items-center justify-center pointer-events-none">
              <EvilEye
                eyeColor="#ea580c"
                backgroundColor="#070907"
                intensity={1.75}
                pupilSize={0.58}
                irisWidth={0.26}
                glowIntensity={0.42}
                scale={0.92}
                noiseScale={1.1}
                pupilFollow={1.15}
                flameSpeed={1.1}
              />
            </div>

            {/* Overlay Typography & Brand Header */}
            <div className="relative z-10 flex flex-col items-center justify-between h-full max-h-[85vh] py-12 text-center pointer-events-none">
              {/* Top Telemetry Header */}
              <motion.div
                className="flex items-center gap-3 px-4 py-1.5 rounded-full border border-orange-500/20 bg-black/40 backdrop-blur-md"
                initial={{ opacity: 0, y: -15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.1 }}
              >
                <div className="w-2 h-2 rounded-full bg-[#ea580c] animate-pulse shadow-[0_0_8px_#ea580c]" />
                <span className="text-[10px] md:text-[11px] font-mono tracking-[0.22em] text-[#d4cfc5] uppercase">
                  DRISHTI <span className="text-[#ea580c] font-bold">//</span> DEFENSIVE ATTACK GRAPH
                </span>
              </motion.div>

              {/* Spacer so the Evil Eye in center is perfectly framed */}
              <div className="my-auto h-40" />

              {/* Bottom Brand Title & Kinetic Tagline */}
              <div className="flex flex-col items-center">
                <motion.h1
                  className="text-3xl md:text-5xl font-black tracking-[0.45em] uppercase text-[#f4f1ea] font-mono flex items-center justify-center pl-[0.45em] mb-2 drop-shadow-[0_0_25px_rgba(234,88,12,0.4)]"
                  initial={{ opacity: 0, y: 15, filter: "blur(8px)" }}
                  animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
                  transition={{ duration: 0.6, delay: 0.25, ease: [0.16, 1, 0.3, 1] }}
                >
                  <span className="sleek-shimmer-text">DRISHTI</span>
                </motion.h1>

                <motion.p
                  className="text-[11px] md:text-xs font-mono tracking-[0.3em] text-[#d4cfc5] uppercase pl-[0.3em]"
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, delay: 0.45, ease: [0.16, 1, 0.3, 1] }}
                >
                  See the invisible. Price the risk.
                </motion.p>
              </div>
            </div>

            {/* Subtle bottom skip hint */}
            <button
              type="button"
              onClick={handleDismiss}
              className="sleek-skip-hint pointer-events-auto"
              aria-label="Skip animation"
            >
              Press ESC or Click to Skip
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Page Content with fluid entrance */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      >
        {children}
      </motion.div>
    </>
  );
}

export default EntryAnimation;

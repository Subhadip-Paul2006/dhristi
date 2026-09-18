import { useState, useEffect } from "react";
import { motion, AnimatePresence, useScroll, useSpring } from "framer-motion";
import { ArrowUp } from "lucide-react";

interface ScrollToTopButtonProps {
  threshold?: number;
  className?: string;
}

/**
 * ScrollToTopButton (21st.dev style)
 * A floating glassmorphic scroll-to-top component with an animated SVG circular progress indicator
 * and tactile spring interactions.
 */
export function ScrollToTopButton({
  threshold = 200,
  className = "",
}: ScrollToTopButtonProps) {
  const [isVisible, setIsVisible] = useState(false);
  const { scrollY, scrollYProgress } = useScroll();
  const smoothProgress = useSpring(scrollYProgress, {
    stiffness: 120,
    damping: 20,
    restDelta: 0.001,
  });

  useEffect(() => {
    return scrollY.on("change", (latest) => {
      setIsVisible(latest > threshold);
    });
  }, [scrollY, threshold]);

  const scrollToTop = () => {
    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  const radius = 20;
  const circumference = 2 * Math.PI * radius;

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0, scale: 0.6, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.6, y: 20 }}
          transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
          className={`fixed bottom-6 right-6 z-50 ${className}`}
        >
          <motion.button
            onClick={scrollToTop}
            whileHover={{ scale: 1.1, y: -3 }}
            whileTap={{ scale: 0.92 }}
            aria-label="Scroll to top"
            className="group relative flex items-center justify-center w-12 h-12 rounded-full bg-black/80 backdrop-blur-xl border border-white/15 text-white shadow-[0_4px_25px_rgba(0,0,0,0.5),0_0_15px_rgba(255,138,0,0.2)] hover:shadow-[0_4px_30px_rgba(255,138,0,0.45)] hover:border-[#ff8a00]/60 transition-colors duration-300 cursor-pointer"
          >
            {/* SVG Circular Progress Ring */}
            <svg
              className="absolute inset-0 w-full h-full -rotate-90 pointer-events-none p-[2px]"
              viewBox="0 0 48 48"
            >
              {/* Background Track */}
              <circle
                cx="24"
                cy="24"
                r={radius}
                fill="none"
                stroke="rgba(255, 255, 255, 0.1)"
                strokeWidth="2.5"
              />
              {/* Animated Progress Ring */}
              <motion.circle
                cx="24"
                cy="24"
                r={radius}
                fill="none"
                stroke="url(#scrollToTopGradient)"
                strokeWidth="2.5"
                strokeDasharray={circumference}
                style={{
                  pathLength: smoothProgress,
                }}
                strokeLinecap="round"
              />
              <defs>
                <linearGradient
                  id="scrollToTopGradient"
                  x1="0%"
                  y1="0%"
                  x2="100%"
                  y2="100%"
                >
                  <stop offset="0%" stopColor="#ff8a00" />
                  <stop offset="100%" stopColor="#ea580c" />
                </linearGradient>
              </defs>
            </svg>

            {/* Centered Arrow Icon with micro hover slide */}
            <ArrowUp
              size={18}
              className="relative z-10 text-white group-hover:text-[#ff8a00] group-hover:-translate-y-0.5 transition-all duration-300 stroke-[2.5]"
            />
          </motion.button>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export default ScrollToTopButton;

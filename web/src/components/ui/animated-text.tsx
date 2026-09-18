import { motion, type Variants } from "framer-motion";
import React, { useState, useEffect } from "react";

interface BlurTextRevealProps {
  text: string;
  className?: string;
  delay?: number;
  duration?: number;
  stagger?: number;
  as?: "h1" | "h2" | "h3" | "p" | "span" | "div";
}

/**
 * BlurTextReveal (21st.dev style)
 * Animates text word-by-word with a soft blur-in filter and upward translation.
 */
export function BlurTextReveal({
  text,
  className = "",
  delay = 0,
  duration = 0.55,
  stagger = 0.07,
  as = "span",
}: BlurTextRevealProps) {
  const words = text.split(" ");
  const Component = motion[as] as any;

  const containerVariants: Variants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: stagger,
        delayChildren: delay,
      },
    },
  };

  const wordVariants: Variants = {
    hidden: {
      opacity: 0,
      y: 16,
      filter: "blur(10px)",
    },
    visible: {
      opacity: 1,
      y: 0,
      filter: "blur(0px)",
      transition: {
        duration,
        ease: [0.2, 0.65, 0.3, 0.9] as const,
      },
    },
  };

  return (
    <Component
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className={className}
      style={{ display: "inline-block" }}
    >
      {words.map((word, i) => (
        <motion.span
          key={i}
          variants={wordVariants}
          style={{ display: "inline-block", marginRight: "0.28em" }}
        >
          {word}
        </motion.span>
      ))}
    </Component>
  );
}

interface AnimatedShimmerTextProps {
  children: React.ReactNode;
  className?: string;
  shimmerColor?: string;
}

/**
 * AnimatedShimmerText (21st.dev style)
 * Adds an iridescent, flowing light sweep across gradient text.
 */
export function AnimatedShimmerText({
  children,
  className = "",
}: AnimatedShimmerTextProps) {
  return (
    <span className={`sceneai-shimmer-text ${className}`}>
      {children}
    </span>
  );
}

interface CyberScrambleTextProps {
  text: string;
  className?: string;
  delay?: number;
  speed?: number;
}

/**
 * CyberScrambleText (21st.dev / Aceternity style)
 * Scrambles characters with cyber glyphs and decrypts into target letters.
 */
const CYBER_GLYPHS = "01#@$%&*<>~/\\{}[]+=";

export function CyberScrambleText({
  text,
  className = "",
  delay = 0,
  speed = 30,
}: CyberScrambleTextProps) {
  const [displayText, setDisplayText] = useState("");

  useEffect(() => {
    let iteration = 0;
    let interval: NodeJS.Timeout;
    const timeout = setTimeout(() => {
      interval = setInterval(() => {
        setDisplayText(
          text
            .split("")
            .map((char, index) => {
              if (char === " ") return " ";
              if (index < iteration) {
                return text[index];
              }
              return CYBER_GLYPHS[Math.floor(Math.random() * CYBER_GLYPHS.length)];
            })
            .join("")
        );

        if (iteration >= text.length) {
          clearInterval(interval);
        }
        iteration += 1 / 2;
      }, speed);
    }, delay * 1000);

    return () => {
      clearTimeout(timeout);
      if (interval) clearInterval(interval);
    };
  }, [text, delay, speed]);

  return <span className={className}>{displayText || text}</span>;
}

interface FlipWordsProps {
  words: string[];
  duration?: number;
  className?: string;
}

/**
 * FlipWords (21st.dev style)
 * Continuously cycles through words with letter-by-letter blur reveal and 3D fluid transitions.
 */
export function FlipWords({
  words,
  duration = 3200,
  className = "",
}: FlipWordsProps) {
  const [currentWord, setCurrentWord] = useState(words[0]);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentWord((prev) => {
        const nextIdx = (words.indexOf(prev) + 1) % words.length;
        return words[nextIdx];
      });
    }, duration);
    return () => clearInterval(interval);
  }, [words, duration]);

  return (
    <span className="inline-block relative overflow-hidden align-middle">
      <motion.span
        key={currentWord}
        initial={{ opacity: 0, y: 16, filter: "blur(8px)" }}
        animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
        exit={{ opacity: 0, y: -16, filter: "blur(8px)" }}
        transition={{
          duration: 0.5,
          ease: [0.2, 0.65, 0.3, 0.9],
        }}
        className={`inline-block ${className}`}
      >
        {currentWord}
      </motion.span>
    </span>
  );
}


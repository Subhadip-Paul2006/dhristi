import { useEffect, useRef, useState } from "react";

export function useAnimatedCounter(
 target: number,
 duration = 2000,
 startOnView = true
) {
 const [value, setValue] = useState(0);
 const ref = useRef<HTMLDivElement>(null);
 const started = useRef(false);

 useEffect(() => {
 if (!startOnView) return;
 const el = ref.current;
 if (!el) return;

 const observer = new IntersectionObserver(
 ([entry]) => {
 if (entry.isIntersecting && !started.current) {
 started.current = true;
 animate();
 observer.disconnect();
 }
 },
 { threshold: 0.3 }
 );

 observer.observe(el);
 return () => observer.disconnect();
 }, [target, duration, startOnView]);

 const animate = () => {
 const start = performance.now();
 const step = (now: number) => {
 const elapsed = now - start;
 const progress = Math.min(elapsed / duration, 1);
 // easeOutExpo
 const eased = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
 setValue(Math.round(eased * target));
 if (progress < 1) requestAnimationFrame(step);
 };
 requestAnimationFrame(step);
 };

 return { value, ref };
}

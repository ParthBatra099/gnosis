import { useEffect, useRef } from 'react';
import type { ReactNode } from 'react';

export const DEMO_WARNING = 'DEMO MODE — Password-only authentication for fictional local accounts. MFA is not being demonstrated.';
export function DemoFrame({ children }: { children: ReactNode }) {
  const frame = useRef<HTMLDivElement>(null);
  const banner = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const update = () => frame.current?.style.setProperty('--demo-banner-height', `${banner.current?.getBoundingClientRect().height || 88}px`);
    update();
    const observer = new ResizeObserver(update);
    if (banner.current) observer.observe(banner.current);
    return () => observer.disconnect();
  }, []);
  return <div className="demo-frame" ref={frame}><div ref={banner} className="demo-banner" role="note" aria-label="Local demonstration warning">{DEMO_WARNING}</div>{children}</div>;
}

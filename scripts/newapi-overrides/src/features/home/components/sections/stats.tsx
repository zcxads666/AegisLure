/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.
*/
import { useCallback, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'

interface CounterProps {
  end: number
  suffix?: string
  prefix?: string
  duration?: number
  decimals?: number
}

function Counter({
  end,
  suffix = '',
  prefix = '',
  duration = 1600,
  decimals = 0,
}: CounterProps) {
  const ref = useRef<HTMLSpanElement>(null)
  const startedRef = useRef(false)
  const formatValue = useCallback(
    (value: number) =>
      decimals > 0 ? value.toFixed(decimals) : Math.round(value).toLocaleString(),
    [decimals]
  )

  const animate = useCallback(() => {
    const element = ref.current
    if (!element) return
    const start = performance.now()
    const step = (now: number) => {
      const progress = Math.min((now - start) / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      element.textContent = `${prefix}${formatValue(eased * end)}${suffix}`
      if (progress < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [end, duration, prefix, suffix, formatValue])

  useEffect(() => {
    const element = ref.current
    if (!element) return
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
    if (mediaQuery.matches) {
      element.textContent = `${prefix}${formatValue(end)}${suffix}`
      return
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !startedRef.current) {
          startedRef.current = true
          animate()
          observer.unobserve(element)
        }
      },
      { threshold: 0.5 }
    )
    observer.observe(element)
    return () => observer.disconnect()
  }, [animate, end, prefix, suffix, formatValue])

  return (
    <span ref={ref} className='tabular-nums'>
      {prefix}0{suffix}
    </span>
  )
}

interface StatsProps {
  className?: string
}

interface StatItem {
  end: number
  suffix: string
  label: string
  decimals?: number
}

export function Stats(_props: StatsProps) {
  const { t } = useTranslation()
  const stats: StatItem[] = [
    { end: 3, suffix: '', label: t('local synthetic protocols') },
    { end: 1, suffix: '', label: t('single-node tenant') },
    { end: 4, suffix: '', label: t('local dashboard surfaces') },
    { end: 0, suffix: '', label: t('external channels enabled') },
  ]

  return (
    <div className='border-border/40 bg-muted/10 relative z-10 border-y'>
      <div className='mx-auto max-w-6xl px-6 py-10 md:py-12'>
        <div className='grid grid-cols-2 gap-8 md:grid-cols-4 md:gap-12'>
          {stats.map((stat) => (
            <div
              key={stat.label}
              className='flex flex-col items-center text-center'
            >
              <span className='text-2xl font-bold tracking-tight md:text-3xl'>
                <Counter
                  end={stat.end}
                  suffix={stat.suffix}
                  decimals={stat.decimals}
                />
              </span>
              <span className='text-muted-foreground mt-1.5 text-xs'>
                {stat.label}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

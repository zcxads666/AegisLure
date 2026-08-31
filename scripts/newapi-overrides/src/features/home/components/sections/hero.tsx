/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.
*/
import { Link } from '@tanstack/react-router'
import {
  ArrowRight,
  BookOpen,
  Database,
  ShieldCheck,
  Sparkles,
  type LucideIcon,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { Button } from '@/components/ui/button'

import { HeroTerminalDemo } from '../hero-terminal-demo'

interface HeroProps {
  className?: string
  isAuthenticated?: boolean
}

export function Hero(props: HeroProps) {
  const { t } = useTranslation()
  const cards: Array<{ icon: LucideIcon; label: string }> = [
    { icon: Database, label: t('Local model catalog') },
    { icon: ShieldCheck, label: t('Scoped key storage') },
    { icon: Sparkles, label: t('Synthetic streaming') },
  ]

  return (
    <section className='relative z-10 overflow-hidden px-6 pt-24 pb-16 md:pt-32 md:pb-24 lg:pt-36 lg:pb-28'>
      <div
        aria-hidden
        className='pointer-events-none absolute inset-0 -z-10 opacity-25 dark:opacity-[0.12]'
        style={{
          background: [
            'radial-gradient(ellipse 60% 50% at 20% 20%, oklch(0.72 0.18 250 / 80%) 0%, transparent 70%)',
            'radial-gradient(ellipse 50% 40% at 80% 15%, oklch(0.65 0.15 200 / 60%) 0%, transparent 70%)',
          ].join(', '),
        }}
      />

      <div className='mx-auto grid max-w-6xl grid-cols-1 items-start gap-12 lg:grid-cols-12 lg:gap-8'>
        <div className='flex flex-col items-start text-left lg:col-span-6'>
          <div className='landing-animate-fade-up mb-5 inline-flex items-center gap-1.5 rounded-full border border-blue-500/20 bg-blue-500/5 px-3 py-1.5 text-[11px] font-medium text-blue-600 opacity-0 shadow-xs dark:border-blue-400/20 dark:bg-blue-400/5 dark:text-blue-400'>
            <Sparkles className='size-3' />
            <span>{t('Local AI Application Infrastructure')}</span>
          </div>

          <h1 className='landing-animate-fade-up text-[clamp(2.25rem,4.5vw,3.25rem)] leading-[1.15] font-bold tracking-tight'>
            {t('Unified API Gateway for')}
            <br />
            <span className='bg-gradient-to-r from-blue-400 via-violet-400 to-purple-500 bg-clip-text text-transparent'>
              {t('Synthetic AI Models')}
            </span>
          </h1>
          <p className='landing-animate-fade-up text-muted-foreground/80 mt-5 max-w-xl text-base leading-relaxed md:text-[15px]'>
            {t(
              'Explore a local model catalog, issue scoped keys, receive deterministic streaming responses, and inspect every usage event without external channels.'
            )}
          </p>

          <div className='landing-animate-fade-up mt-8 flex flex-wrap items-center gap-3'>
            {props.isAuthenticated ? (
              <Button
                className='group h-11 rounded-lg px-5 text-sm font-medium'
                render={<Link to='/dashboard' />}
              >
                {t('Go to Dashboard')}
                <ArrowRight className='ml-1.5 size-4 transition-transform duration-200 group-hover:translate-x-0.5' />
              </Button>
            ) : (
              <Button
                className='group h-11 rounded-lg px-5 text-sm font-medium'
                render={<Link to='/sign-up' />}
              >
                {t('Get Started')}
                <ArrowRight className='ml-1.5 size-4 transition-transform duration-200 group-hover:translate-x-0.5' />
              </Button>
            )}
            <Button
              variant='outline'
              className='group border-border/50 hover:border-border hover:bg-muted/50 inline-flex h-11 items-center gap-1.5 rounded-lg px-5 text-sm font-medium'
              render={<a href='/docs' />}
            >
              <BookOpen className='text-muted-foreground/80 group-hover:text-foreground size-4' />
              <span>{t('Docs')}</span>
            </Button>
          </div>

          <div className='mt-10 grid w-full max-w-xl grid-cols-1 gap-3 sm:grid-cols-3'>
            {cards.map(({ icon: Icon, label }) => (
              <div
                key={String(label)}
                className='border-border/40 bg-muted/15 text-muted-foreground flex items-center gap-2 rounded-xl border px-3 py-3 text-xs'
              >
                <Icon className='text-primary size-4 shrink-0' />
                <span>{label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className='landing-animate-fade-up flex w-full justify-center lg:col-span-6'>
          <HeroTerminalDemo className='mt-8 lg:mt-0' />
        </div>
      </div>
    </section>
  )
}

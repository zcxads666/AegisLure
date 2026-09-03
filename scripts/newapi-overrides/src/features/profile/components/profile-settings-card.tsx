/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.
*/
import { Link2, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { TitledCard } from '@/components/ui/titled-card'

import type { UserProfile } from '../types'

interface ProfileSettingsCardProps {
  profile: UserProfile | null
  loading: boolean
  onProfileUpdate: () => void
}

/**
 * The upstream settings card includes email, OAuth, webhook and notification
 * controls. They are intentionally read-only/omitted for the bait; the only
 * application egress exception is the separate, operator-selected provider
 * lookup path.
 */
export function ProfileSettingsCard({
  profile: _profile,
  loading: _loading,
  onProfileUpdate: _onProfileUpdate,
}: ProfileSettingsCardProps) {
  const { t } = useTranslation()

  return (
    <TitledCard
      title={t('Settings')}
      description={t('Personal settings and profile management.')}
      icon={<Link2 className='h-4 w-4' />}
      iconTone='info'
      disableHoverEffect
    >
      <div className='bg-muted/20 flex items-start gap-3 rounded-xl border p-3 text-sm'>
        <ShieldCheck className='text-success mt-0.5 h-4 w-4 shrink-0' />
        <div className='space-y-1'>
          <p className='font-medium'>{t('Account preferences')}</p>
          <p className='text-muted-foreground text-xs leading-relaxed'>
            {t('Review your account preferences and security settings.')}
          </p>
        </div>
      </div>
    </TitledCard>
  )
}

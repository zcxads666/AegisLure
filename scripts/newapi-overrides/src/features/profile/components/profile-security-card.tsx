/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.
*/
import { Shield } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { IconBadge } from '@/components/ui/icon-badge'
import { Skeleton } from '@/components/ui/skeleton'
import { TitledCard } from '@/components/ui/titled-card'
import { useDialogs } from '@/hooks/use-dialog'

import type { UserProfile } from '../types'
import { ChangePasswordDialog } from './dialogs/change-password-dialog'

interface ProfileSecurityCardProps {
  profile: UserProfile | null
  loading: boolean
}

export function ProfileSecurityCard({
  profile,
  loading,
}: ProfileSecurityCardProps) {
  const { t } = useTranslation()
  const dialogs = useDialogs<'password'>()

  if (loading) {
    return (
      <Card data-card-hover='false' className='gap-0 overflow-hidden py-0'>
        <CardHeader className='border-b p-3 !pb-3 sm:p-5 sm:!pb-5'>
          <Skeleton className='h-6 w-32' />
          <Skeleton className='mt-2 h-4 w-48' />
        </CardHeader>
        <CardContent className='space-y-3 p-3 sm:p-5'>
          <Skeleton className='h-16 w-full' />
        </CardContent>
      </Card>
    )
  }

  if (!profile) return null

  return (
    <>
      <TitledCard
        title={t('Security')}
        description={t('Manage your security settings and account access')}
        icon={<Shield className='h-4 w-4' />}
        iconTone='success'
        disableHoverEffect
      >
        <button
          type='button'
          onClick={() => dialogs.open('password')}
          className='flex w-full items-center gap-3 rounded-lg border p-3 text-left md:max-w-sm md:p-4'
        >
          <IconBadge tone='neutral' size='sm'>
            <Shield />
          </IconBadge>
          <div className='min-w-0'>
            <p className='text-sm font-medium'>{t('Change Password')}</p>
            <p className='text-muted-foreground line-clamp-2 text-xs'>
              {t('Update your password to keep your account secure')}
            </p>
          </div>
        </button>
      </TitledCard>

      <ChangePasswordDialog
        open={dialogs.isOpen('password')}
        onOpenChange={(open) =>
          open ? dialogs.open('password') : dialogs.close('password')
        }
        username={profile.username}
      />
    </>
  )
}

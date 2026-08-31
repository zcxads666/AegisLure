/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.
*/
import { Activity, FileText, Key, LayoutDashboard, User } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import type { SidebarData } from '@/components/layout/types'

/**
 * Standalone tenant navigation. Admin, billing, wallet, playground and
 * channel-management surfaces are intentionally not reachable from the UI.
 */
export function useSidebarData(): SidebarData {
  const { t } = useTranslation()

  return {
    navGroups: [
      {
        id: 'general',
        title: t('General'),
        items: [
          { title: t('Overview'), url: '/dashboard/overview', icon: Activity },
          {
            title: t('Dashboard'),
            url: '/dashboard/models',
            icon: LayoutDashboard,
          },
          { title: t('API Keys'), url: '/keys', icon: Key },
          {
            title: t('Usage Logs'),
            url: '/usage-logs/common',
            icon: FileText,
          },
        ],
      },
      {
        id: 'personal',
        title: t('Personal'),
        items: [{ title: t('Profile'), url: '/profile', icon: User }],
      },
    ],
  }
}

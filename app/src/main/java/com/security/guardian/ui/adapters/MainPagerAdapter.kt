package com.security.guardian.ui.adapters

import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.security.guardian.ui.fragments.DashboardFragment
import com.security.guardian.ui.fragments.ThreatsFragment
import com.security.guardian.ui.fragments.RecoveryFragment
import com.security.guardian.ui.fragments.SettingsFragment

class MainPagerAdapter(activity: FragmentActivity) : FragmentStateAdapter(activity) {
    
    override fun getItemCount() = 4
    
    override fun createFragment(position: Int): Fragment {
        return when (position) {
            0 -> DashboardFragment()
            1 -> ThreatsFragment()
            2 -> RecoveryFragment()
            3 -> SettingsFragment()
            else -> DashboardFragment()
        }
    }
}

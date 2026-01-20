package com.security.guardian.ui.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.security.guardian.R
import com.security.guardian.data.entities.ThreatEvent

class ThreatAdapter(
    private val threats: List<ThreatEvent>,
    private val onItemClick: (ThreatEvent) -> Unit
) : RecyclerView.Adapter<ThreatAdapter.ViewHolder>() {
    
    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val typeText: TextView = view.findViewById(R.id.threatTypeText)
        val appNameText: TextView = view.findViewById(R.id.appNameText)
        val descriptionText: TextView = view.findViewById(R.id.descriptionText)
        val severityChip: com.google.android.material.chip.Chip = view.findViewById(R.id.severityChip)
        val severityIndicator: View = view.findViewById(R.id.severityIndicator)
        val timestampText: TextView = view.findViewById(R.id.timestampText)
        val viewDetailsButton: com.google.android.material.button.MaterialButton = view.findViewById(R.id.viewDetailsButton)
    }
    
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_threat, parent, false)
        return ViewHolder(view)
    }
    
    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val threat = threats[position]
        
        holder.typeText.text = threat.type ?: "Unknown"
        holder.appNameText.text = threat.packageName ?: "Unknown"
        holder.descriptionText.text = threat.description
        
        // Set severity chip
        holder.severityChip.text = threat.severity
        val bgColor = when (threat.severity) {
            "CRITICAL" -> R.color.critical_red
            "HIGH" -> R.color.high_orange
            "MEDIUM" -> R.color.medium_yellow
            else -> R.color.low_blue
        }
        holder.severityChip.setChipBackgroundColorResource(bgColor)
        holder.severityIndicator.setBackgroundColor(
            holder.itemView.context.getColor(bgColor)
        )
        
        // Format timestamp
        val timeAgo = formatTimeAgo(threat.timestamp)
        holder.timestampText.text = timeAgo
        
        // Make view details button work
        holder.viewDetailsButton.setOnClickListener {
            onItemClick(threat)
        }
        
        // Also allow clicking the entire card
        holder.itemView.setOnClickListener {
            onItemClick(threat)
        }
    }
    
    private fun formatTimeAgo(timestamp: Long): String {
        val now = System.currentTimeMillis()
        val diff = now - timestamp
        val seconds = diff / 1000
        val minutes = seconds / 60
        val hours = minutes / 60
        val days = hours / 24
        
        return when {
            days > 0 -> "$days day${if (days > 1) "s" else ""} ago"
            hours > 0 -> "$hours hour${if (hours > 1) "s" else ""} ago"
            minutes > 0 -> "$minutes minute${if (minutes > 1) "s" else ""} ago"
            else -> "Just now"
        }
    }
    
    override fun getItemCount() = threats.size
}

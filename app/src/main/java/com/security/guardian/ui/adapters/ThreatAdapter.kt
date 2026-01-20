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
        val severityText: TextView = view.findViewById(R.id.severityText)
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
        holder.severityText.text = "Severity: ${threat.severity}"
        
        holder.itemView.setOnClickListener {
            onItemClick(threat)
        }
    }
    
    override fun getItemCount() = threats.size
}

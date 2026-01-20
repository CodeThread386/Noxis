package com.security.guardian.ui.fragments

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.security.guardian.R
import com.security.guardian.ui.ThreatDetailActivity
import com.security.guardian.ui.adapters.ThreatAdapter
import com.security.guardian.viewmodel.RansomwareViewModel

class ThreatsFragment : Fragment() {
    
    private lateinit var viewModel: RansomwareViewModel
    private lateinit var recyclerView: RecyclerView
    
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        // Use dashboard layout if threats layout doesn't exist
        return try {
            inflater.inflate(R.layout.fragment_threats, container, false)
        } catch (e: Exception) {
            inflater.inflate(R.layout.fragment_dashboard, container, false)
        }
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        viewModel = ViewModelProvider(requireActivity())[RansomwareViewModel::class.java]
        
        recyclerView = view.findViewById(R.id.threatsRecyclerView)
        recyclerView.layoutManager = LinearLayoutManager(requireContext())
        
        try {
            recyclerView = view.findViewById(R.id.threatsRecyclerView)
            recyclerView.layoutManager = LinearLayoutManager(requireContext())
            
            viewModel.allThreats.observe(viewLifecycleOwner) { threats ->
                recyclerView.adapter = ThreatAdapter(threats ?: emptyList()) { threat ->
                    val intent = Intent(requireContext(), ThreatDetailActivity::class.java).apply {
                        putExtra("threat_id", threat.id)
                        putExtra("threat_type", threat.type ?: "")
                        putExtra("description", threat.description)
                        putExtra("severity", threat.severity)
                        putExtra("package_name", threat.packageName ?: "")
                    }
                    startActivity(intent)
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("ThreatsFragment", "Error setting up threats list", e)
        }
    }
}

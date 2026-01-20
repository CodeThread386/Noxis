package com.security.guardian.ui.fragments

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import com.security.guardian.R
import com.security.guardian.viewmodel.RansomwareViewModel

class DashboardFragment : Fragment() {
    
    private lateinit var viewModel: RansomwareViewModel
    private lateinit var threatsDetectedText: TextView
    
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_dashboard, container, false)
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        viewModel = ViewModelProvider(requireActivity())[RansomwareViewModel::class.java]
        
        threatsDetectedText = view.findViewById(R.id.threatsDetectedText)
        
        viewModel.activeThreats.observe(viewLifecycleOwner) { threats ->
            threatsDetectedText.text = "${threats?.size ?: 0}"
        }
    }
}

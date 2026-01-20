package com.security.guardian.ui.fragments

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.security.guardian.R
import com.security.guardian.data.RansomwareDatabase
import kotlinx.coroutines.launch

class RecoveryFragment : Fragment() {
    
    private lateinit var snapshotCountText: TextView
    private lateinit var noSnapshotsLayout: LinearLayout
    
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_recovery, container, false)
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        snapshotCountText = view.findViewById(R.id.snapshotCountText)
        noSnapshotsLayout = view.findViewById(R.id.noSnapshotsLayout)
        
        view.findViewById<com.google.android.material.button.MaterialButton>(R.id.restoreAllButton)?.setOnClickListener {
            android.widget.Toast.makeText(requireContext(), "Restoring all files from snapshots...", android.widget.Toast.LENGTH_SHORT).show()
        }
        
        view.findViewById<com.google.android.material.button.MaterialButton>(R.id.selectiveRestoreButton)?.setOnClickListener {
            android.widget.Toast.makeText(requireContext(), "Opening file picker...", android.widget.Toast.LENGTH_SHORT).show()
        }
        
        loadSnapshotCount()
    }
    
    private fun loadSnapshotCount() {
        lifecycleScope.launch {
            try {
                val db = RansomwareDatabase.getDatabase(requireContext())
                val snapshots = db.snapshotMetadataDao().getAllSnapshots()
                val count = snapshots.size
                
                snapshotCountText.text = "$count snapshot${if (count != 1) "s" else ""}"
                
                if (count == 0) {
                    noSnapshotsLayout.visibility = View.VISIBLE
                } else {
                    noSnapshotsLayout.visibility = View.GONE
                }
            } catch (e: Exception) {
                Log.e("RecoveryFragment", "Error loading snapshots", e)
                snapshotCountText.text = "0 snapshots"
                noSnapshotsLayout.visibility = View.VISIBLE
            }
        }
    }
}

@file:OptIn(ExperimentalMaterial3Api::class)
package com.aliddell.universalauth

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aliddell.universalauth.data.AuthRequest
import com.aliddell.universalauth.data.DefaultAuthRepository

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val repository = DefaultAuthRepository()
        setContent {
            val authViewModel: AuthViewModel = viewModel(factory = AuthViewModel.Factory(repository))
            val state = authViewModel.uiState.collectAsState()
            PendingRequestsScreen(
                state = state.value,
                onRefresh = { authViewModel.refresh() },
                onDecide = { id, approved -> authViewModel.decide(id, approved) }
            )
        }
    }
}

@Composable
fun PendingRequestsScreen(
    state: AuthViewModel.UiState,
    onRefresh: () -> Unit,
    onDecide: (String, Boolean) -> Unit
) {
    Scaffold(
        topBar = { TopAppBar(title = { Text("Universal Auth") }) }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
        ) {
            Text("Broker: 192.168.1.167")
            Text("Status: ${state.status}")
            Spacer(modifier = Modifier.height(8.dp))
            Button(onClick = onRefresh) { Text("Refresh") }
            Spacer(modifier = Modifier.height(8.dp))
            state.error?.let { Text("Error: $it", color = MaterialTheme.colorScheme.error) }
            if (state.loading) CircularProgressIndicator()
            if (!state.loading && state.requests.isEmpty()) Text("No pending requests")
            LazyColumn(contentPadding = PaddingValues(vertical = 8.dp)) {
                items(state.requests) { request ->
                    RequestCard(request, onDecide)
                }
            }
        }
    }
}

@Composable
fun RequestCard(request: AuthRequest, onDecide: (String, Boolean) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(request.source, style = MaterialTheme.typography.titleMedium)
            Text("${request.kind} - ${request.resource}")
            Text(request.message)
            Text("Created: ${request.createdAt}")
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Button(onClick = { onDecide(request.id, false) }) { Text("Deny") }
                Button(onClick = { onDecide(request.id, true) }) { Text("Approve") }
            }
        }
    }
}

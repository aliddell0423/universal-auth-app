package com.aliddell.universalauth

import com.aliddell.universalauth.data.AuthRepository
import com.aliddell.universalauth.data.AuthRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AuthViewModelTest {
    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun refresh_populatesPendingRequests() {
        val request = AuthRequest(
            id = "1",
            source = "pc",
            kind = "test",
            resource = "dev",
            message = "msg",
            challenge = "challenge",
            status = "pending",
            createdAt = "2026-08-30T12:00:00Z",
            decidedAt = null
        )
        val viewModel = AuthViewModel(FakeAuthRepository(requests = listOf(request)))
        viewModel.refresh()
        testDispatcher.scheduler.advanceUntilIdle()

        val state = viewModel.uiState.value
        assertEquals("connected", state.status)
        assertEquals(1, state.requests.size)
        assertNull(state.error)
    }

    @Test
    fun refresh_setsUnreachableOnHealthFailure() {
        val viewModel = AuthViewModel(FakeAuthRepository(throwHealth = true))
        viewModel.refresh()
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals("unreachable", viewModel.uiState.value.status)
    }

    @Test
    fun registerDevice_updatesDeviceRegistered() {
        val viewModel = AuthViewModel(FakeAuthRepository())
        viewModel.registerDevice("id", "Pixel 10", "ECDSA_P256_SHA256", "pubkey")
        testDispatcher.scheduler.advanceUntilIdle()

        assertTrue(viewModel.uiState.value.deviceRegistered)
        assertNull(viewModel.uiState.value.error)
    }

    @Test
    fun submitSignedApproval_refreshesList() {
        val request = AuthRequest(
            id = "1",
            source = "pc",
            kind = "test",
            resource = "dev",
            message = "msg",
            challenge = "challenge",
            status = "pending",
            createdAt = "2026-08-30T12:00:00Z",
            decidedAt = null
        )
        val viewModel = AuthViewModel(FakeAuthRepository(requests = listOf(request)))
        viewModel.submitSignedApproval("1", "id", "signature")
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals("connected", viewModel.uiState.value.status)
    }

    @Test
    fun deny_refreshesListWithoutApproval() {
        val request = AuthRequest(
            id = "1",
            source = "pc",
            kind = "test",
            resource = "dev",
            message = "msg",
            challenge = "challenge",
            status = "pending",
            createdAt = "2026-08-30T12:00:00Z",
            decidedAt = null
        )
        val viewModel = AuthViewModel(FakeAuthRepository(requests = listOf(request)))
        viewModel.decide("1", false)
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals("connected", viewModel.uiState.value.status)
    }

    private class FakeAuthRepository(
        private val requests: List<AuthRequest> = emptyList(),
        private val throwHealth: Boolean = false
    ) : AuthRepository {
        override suspend fun checkHealth(): Result<String> =
            if (throwHealth) Result.failure(Exception("network"))
            else Result.success("{\"status\":\"ok\"}")

        override suspend fun getPendingRequests(): Result<List<AuthRequest>> =
            Result.success(requests)

        override suspend fun registerDevice(
            deviceId: String,
            name: String,
            algorithm: String,
            publicKey: String
        ): Result<Unit> = Result.success(Unit)

        override suspend fun submitSignedApproval(
            id: String,
            deviceId: String,
            signature: String
        ): Result<AuthRequest> = Result.success(requests.first { it.id == id })

        override suspend fun submitDenial(id: String): Result<AuthRequest> =
            Result.success(requests.first { it.id == id })
    }
}

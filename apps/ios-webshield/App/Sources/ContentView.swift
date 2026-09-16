import SwiftUI
import WebShieldCore

struct ContentView: View {
    @StateObject private var model = WebShieldViewModel()
    @State private var presentsClearConfirmation = false

    var body: some View {
        NavigationStack {
            List {
                statusSection
                protectionSection
                enablementSection
                activitySection
                privacySection
            }
            .navigationTitle(Text("app_name"))
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task { await model.reload() }
                    } label: {
                        Label("refresh", systemImage: "arrow.clockwise")
                    }
                    .accessibilityIdentifier("audit.refresh")
                }
            }
            .task {
                await model.reload()
            }
            .confirmationDialog(
                Text("clear_title"),
                isPresented: $presentsClearConfirmation,
                titleVisibility: .visible
            ) {
                Button("clear", role: .destructive) {
                    Task { await model.clearHistory() }
                }
                Button("cancel", role: .cancel) {}
            } message: {
                Text("clear_message")
            }
        }
    }

    private var statusSection: some View {
        Section {
            HStack(spacing: 12) {
                Image(systemName: model.isEnabled ? "checkmark.shield.fill" : "shield.slash")
                    .font(.title2)
                    .foregroundStyle(model.isEnabled ? .green : .secondary)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text("limited_badge")
                        .font(.headline)
                    Text(statusKey)
                        .font(.subheadline)
                        .foregroundStyle(Color.primary)
                        .accessibilityIdentifier("status.value")
                }
            }
        }
    }

    @ViewBuilder
    private var protectionSection: some View {
        Section {
            Toggle(
                "privacy_consent",
                isOn: Binding(
                    get: { model.hasAcceptedPrivacy },
                    set: { accepted in
                        Task { await model.setPrivacyAccepted(accepted) }
                    }
                )
            )
            .disabled(!model.storageAvailable)
            .accessibilityIdentifier("privacy.toggle")

            Toggle(
                "enable_protection",
                isOn: Binding(
                    get: { model.isEnabled },
                    set: { enabled in
                        Task { await model.setEnabled(enabled) }
                    }
                )
            )
            .disabled(!model.hasAcceptedPrivacy || !model.storageAvailable)
            .accessibilityIdentifier("protection.toggle")

            Text("protection_note")
                .font(.footnote)
                .foregroundStyle(Color.primary)
        } header: {
            Text("section_protection").foregroundStyle(Color.primary)
        }

        Section {
            Label("scope_body", systemImage: "safari")
                .font(.callout)
                .accessibilityIdentifier("scope.boundary")
        } header: {
            Text("scope_title").foregroundStyle(Color.primary)
        }
    }

    private var enablementSection: some View {
        Section {
            Label("enable_step_1", systemImage: "1.circle")
                .accessibilityIdentifier("enable.step1")
            Label("enable_step_2", systemImage: "2.circle")
            Label("enable_step_3", systemImage: "3.circle")
            Text("enable_status_note")
                .font(.footnote)
                .foregroundStyle(Color.primary)
        } header: {
            Text("section_enable").foregroundStyle(Color.primary)
        }
    }

    private var activitySection: some View {
        Section {
            if model.records.isEmpty {
                Text("no_activity")
                    .foregroundStyle(Color.primary)
                    .accessibilityIdentifier("audit.empty")
            } else {
                ForEach(model.records.prefix(25)) { record in
                    AuditRecordRow(record: record)
                }
            }

            Button("clear_history", role: .destructive) {
                presentsClearConfirmation = true
            }
            .disabled(!model.canClearHistory)
            .accessibilityIdentifier("audit.clear")
        } header: {
            Text("section_activity").foregroundStyle(Color.primary)
        } footer: {
            Text("audit_description").foregroundStyle(Color.primary)
        }
    }

    private var privacySection: some View {
        Section {
            Text("privacy_note")
                .font(.callout)
                .accessibilityIdentifier("privacy.note")
            if !model.storageAvailable {
                Label("storage_unavailable", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(Color.primary)
                    .accessibilityIdentifier("storage.error")
            }
        } header: {
            Text("section_privacy").foregroundStyle(Color.primary)
        }
    }

    private var statusKey: LocalizedStringKey {
        if !model.storageAvailable { return "status_unavailable" }
        return model.isEnabled ? "status_ready" : "status_off"
    }
}

private struct AuditRecordRow: View {
    let record: AuditRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(record.ruleID)
                    .font(.headline.monospaced())
                Spacer()
                Text(record.action == "blocked" ? String(localized: "audit_blocked") : record.action)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(record.origin)
                .font(.subheadline)
                .lineLimit(1)
            Text(record.occurredAt, style: .relative)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }
}

#Preview {
    ContentView()
}

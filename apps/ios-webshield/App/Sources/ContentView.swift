import SwiftUI
import UIKit
import WebShieldCore

struct ContentView: View {
    @StateObject private var model = WebShieldViewModel()
    @State private var presentsClearConfirmation = false

    var body: some View {
        NavigationStack {
            Group {
                // 旧 Xcode 的 SDK 没有此声明；运行时版本判断不能替代编译期隔离。
                #if compiler(>=6.2)
                if #available(iOS 26.0, *) {
                    pageContent.scrollEdgeEffectHidden(true, for: .top)
                } else {
                    pageContent
                }
                #else
                pageContent
                #endif
            }
            .navigationTitle(Text("app_name"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(Color(uiColor: .systemGroupedBackground), for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
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

    private var pageContent: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                statusSection
                protectionSection
                enablementSection
                activitySection
                privacySection
            }
            .padding()
        }
        .background(Color(uiColor: .systemGroupedBackground))
    }

    private var statusSection: some View {
        GroupBox {
            HStack(spacing: 12) {
                Image(systemName: model.isEnabled ? "checkmark.shield.fill" : "shield.slash")
                    .font(.title2)
                    .foregroundStyle(model.isEnabled ? .green : .secondary)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text("limited_badge")
                        .accessibilityIdentifier("status.badge")
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
        NativeSection {
            Toggle(
                "privacy_consent",
                isOn: Binding(
                    get: { model.hasAcceptedPrivacy },
                    set: { accepted in
                        Task { await model.setPrivacyAccepted(accepted) }
                    }
                )
            )
            .frame(minHeight: 44)
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
            .frame(minHeight: 44)
            .disabled(!model.hasAcceptedPrivacy || !model.storageAvailable)
            .accessibilityIdentifier("protection.toggle")

            Text("protection_note")
                .accessibilityIdentifier("protection.note")
                .font(.footnote)
                .foregroundStyle(Color.primary)
        } header: {
            Text("section_protection").foregroundStyle(Color.primary)
                .accessibilityIdentifier("section.protection")
        }

        NativeSection {
            ReadableLabel("scope_body", systemImage: "safari", style: .callout, identifier: "scope.boundary")
        } header: {
            Text("scope_title").foregroundStyle(Color.primary)
                .accessibilityIdentifier("section.scope")
        }
    }

    private var enablementSection: some View {
        NativeSection {
            ReadableLabel("enable_step_1", systemImage: "1.circle", identifier: "enable.step1")
            ReadableLabel("enable_step_2", systemImage: "2.circle", identifier: "enable.step2")
            ReadableLabel("enable_step_3", systemImage: "3.circle", identifier: "enable.step3")
            Text("enable_status_note")
                .accessibilityIdentifier("enable.note")
                .font(.footnote)
                .foregroundStyle(Color.primary)
        } header: {
            Text("section_enable").foregroundStyle(Color.primary)
                .accessibilityIdentifier("section.enable")
        }
    }

    @ViewBuilder
    private var activitySection: some View {
        NativeSection {
            if model.records.isEmpty {
                Text("no_activity")
                    .foregroundStyle(Color.primary)
                    .accessibilityIdentifier("audit.empty")
            } else {
                ForEach(model.records.prefix(25)) { record in
                    AuditRecordRow(record: record)
                }
            }

            Button(role: .destructive) {
                presentsClearConfirmation = true
            } label: {
                Text("clear_history").frame(minHeight: 44)
            }
            .disabled(!model.canClearHistory)
            .accessibilityIdentifier("audit.clear")
        } header: {
            Text("section_activity").foregroundStyle(Color.primary)
                .accessibilityIdentifier("section.activity")
        }
        ReadableText(key: "audit_description", style: .footnote, identifier: "audit.note")
    }

    private var privacySection: some View {
        NativeSection {
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
                .accessibilityIdentifier("section.privacy")
        }
    }

    private var statusKey: LocalizedStringKey {
        if !model.storageAvailable { return "status_unavailable" }
        return model.isEnabled ? "status_ready" : "status_off"
    }
}

// 本页内容有上限；区段使用统一的纵向布局和系统颜色。
private struct NativeSection<Content: View, Header: View>: View {
    @ViewBuilder let content: Content
    @ViewBuilder let header: Header

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
                .font(.headline)
                .accessibilityAddTraits(.isHeader)
            VStack(alignment: .leading, spacing: 16) {
                content
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .lineSpacing(2)
            .fixedSize(horizontal: false, vertical: true)
            .padding(16)
            .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16))
        }
    }
}

// 多行说明使用原生动态字体和完整的固有高度。
private struct ReadableText: UIViewRepresentable {
    let key: String
    var style: UIFont.TextStyle = .body
    let identifier: String

    func makeUIView(context: Context) -> UILabel {
        let label = UILabel()
        label.numberOfLines = 0
        label.lineBreakMode = .byWordWrapping
        label.adjustsFontForContentSizeCategory = true
        label.setContentCompressionResistancePriority(.required, for: .vertical)
        return label
    }

    func updateUIView(_ label: UILabel, context: Context) {
        label.text = String(localized: String.LocalizationValue(key))
        label.font = UIFont.preferredFont(forTextStyle: style, compatibleWith: label.traitCollection)
        label.textColor = .label
        label.accessibilityIdentifier = identifier
    }

    func sizeThatFits(_ proposal: ProposedViewSize, uiView: UILabel, context: Context) -> CGSize? {
        guard let width = proposal.width else { return nil }
        let size = uiView.sizeThatFits(CGSize(width: width, height: .greatestFiniteMagnitude))
        return CGSize(width: width, height: ceil(size.height))
    }
}

private struct ReadableLabel: View {
    let key: String
    let systemImage: String
    let style: UIFont.TextStyle
    let identifier: String

    init(_ key: String, systemImage: String, style: UIFont.TextStyle = .body, identifier: String) {
        self.key = key
        self.systemImage = systemImage
        self.style = style
        self.identifier = identifier
    }

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: systemImage).accessibilityHidden(true)
            ReadableText(key: key, style: style, identifier: identifier)
        }
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

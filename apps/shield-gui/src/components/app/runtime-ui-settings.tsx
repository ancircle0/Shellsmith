import { SelectInput, TextInput } from "@/components/app/common";
import type { Locale } from "@/lib/i18n";
import type { RuntimeUiProtection } from "@/lib/tauri";

export function RuntimeUiSettings({ value, onChange, locale, disabled, aab = false }: {
  value: RuntimeUiProtection;
  onChange: (value: RuntimeUiProtection) => void;
  locale: Locale;
  disabled: boolean;
  aab?: boolean;
}) {
  const zh = locale === "zh";
  const names = (text: string) => text.split(/[,\s]+/).filter(Boolean);
  return <fieldset disabled={disabled} className="space-y-4 rounded-xl border p-4">
    <legend className="px-1 text-sm font-medium">{zh ? "界面与调试保护" : "UI & debugging protection"}</legend>
    <label className="flex items-center justify-between gap-3 text-sm">
      {zh ? "防截图与录屏" : "Protect screenshots and recording"}
      <input type="checkbox" checked={value.secure_screen} onChange={(e) => onChange({ ...value, secure_screen: e.target.checked, screen_exempt_activities: e.target.checked ? value.screen_exempt_activities : [] })} />
    </label>
    <p className="text-xs leading-5 text-muted-foreground">{zh ? "保护 Activity 和可识别的 Dialog 窗口；不阻止视图树读取，Root/系统修改可能绕过。" : "Protects activities and recognized dialog windows. Does not hide the view tree; modified systems can bypass it."}</p>
    {value.secure_screen && <label className="block space-y-2 text-sm">
      <span>{zh ? "允许截图的完整 Activity 类名（逗号分隔）" : "Screenshot exemptions: full activity names, comma separated"}</span>
      <TextInput key={value.screen_exempt_activities.join(",")} defaultValue={value.screen_exempt_activities.join(", ")} onBlur={(e) => onChange({ ...value, screen_exempt_activities: names(e.target.value) })} placeholder="com.example.ShareActivity" />
    </label>}
    <label className="block space-y-2 text-sm">
      <span>{zh ? "ADB 调试环境策略" : "ADB environment policy"}</span>
      <SelectInput value={value.adb_policy} onChange={(e) => onChange({ ...value, adb_policy: e.target.value as RuntimeUiProtection["adb_policy"] })}>
        <option value="off">{zh ? "关闭" : "Off"}</option>
        <option value="report">{zh ? "仅记录" : "Report only"}</option>
        <option value="block">{zh ? "限制运行" : "Block execution"}</option>
      </SelectInput>
    </label>
    <p className="text-xs leading-5 text-muted-foreground">{zh ? "检测调试开关，不代表正在逆向。限制模式在开启或无法读取状态时拒绝运行，可能影响开发机与特殊 ROM；建议先用仅记录模式验证。" : "Checks debugging settings, not reverse engineering activity. Block mode denies enabled or unreadable states; validate report mode on your devices first."}</p>
    <label className="flex items-center justify-between gap-3 text-sm">
      {zh ? "前台持续检查调试与注入环境" : "Recheck debugging and injection while in foreground"}
      <input type="checkbox" checked={value.runtime_recheck} onChange={(e) => onChange({ ...value, runtime_recheck: e.target.checked })} />
    </label>
    {!aab && <>
      <label className="flex items-center justify-between gap-3 text-sm">
        {zh ? "资源 ID 名称混淆" : "Obfuscate resource ID names"}
        <input type="checkbox" checked={value.obfuscate_resource_names} onChange={(e) => onChange({ ...value, obfuscate_resource_names: e.target.checked, resource_name_keep: e.target.checked ? value.resource_name_keep : [] })} />
      </label>
      <p className="text-xs leading-5 text-muted-foreground">{zh ? "只修改可确认安全的 id 名称。动态名称查询、Native/资产引用无法确认时保留并报告；不隐藏界面文字。" : "Renames safe ID entries only. Dynamic lookup and opaque native/assets are retained and reported. Visible text stays readable."}</p>
      {value.obfuscate_resource_names && <label className="block space-y-2 text-sm">
        <span>{zh ? "保留的资源名称（逗号分隔）" : "Resource names to keep, comma separated"}</span>
        <TextInput key={value.resource_name_keep.join(",")} defaultValue={value.resource_name_keep.join(", ")} onBlur={(e) => onChange({ ...value, resource_name_keep: names(e.target.value) })} placeholder="login_button, share_button" />
      </label>}
    </>}
    {aab && <p className="text-xs text-muted-foreground">{zh ? "AAB 暂不支持资源名称混淆。" : "Resource name obfuscation is not yet available for AAB."}</p>}
  </fieldset>;
}

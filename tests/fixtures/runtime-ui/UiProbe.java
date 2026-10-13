package dev.mocika.shield.uiprobe;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.os.Bundle;
import android.util.Log;
import android.view.Window;
import android.view.WindowManager;
import android.widget.TextView;

public class UiProbe extends Activity {
    private Dialog dialog;
    public static class ShareActivity extends UiProbe { }
    private static class ProbeDialog extends Dialog {
        ProbeDialog(Activity owner) { super(owner); }
        @Override public void show() { super.show(); }
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView text = new TextView(this);
        text.setId(R.id.private_action);
        text.setText("Shellsmith 界面保护测试\nliteral_action");
        text.setTextSize(28);
        text.setBackgroundColor(0xff66cc99);
        setContentView(text);
        if (findViewById(R.id.private_action) != text) throw new AssertionError("数值 ID 引用损坏");
        // 独立常量必须被名称混淆器保留。
        Log.i("UiProbe", "literal_action");
        if (getIntent().getBooleanExtra("builder", false)) {
            dialog = new AlertDialog.Builder(this).setMessage("Builder 窗口测试").show();
        } else {
            dialog = new ProbeDialog(this);
            TextView inside = new TextView(this); inside.setText("Dialog 窗口测试"); inside.setTextSize(32);
            dialog.setContentView(inside);
            if (getIntent().getBooleanExtra("dialog", true)) dialog.show();
        }
        exercise(getWindow());
        exercise(dialog.getWindow());
    }
    private static void exercise(Window window) {
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
        window.setFlags(0, WindowManager.LayoutParams.FLAG_SECURE);
        WindowManager.LayoutParams params = window.getAttributes();
        params.flags &= ~WindowManager.LayoutParams.FLAG_SECURE;
        window.setAttributes(params);
    }
    @Override public void onResume() {
        super.onResume();
        getWindow().getDecorView().post(() -> {
            boolean expected = getIntent().getBooleanExtra("expect_secure", false);
            boolean activitySecure = (getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE) != 0;
            boolean dialogSecure = (dialog.getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE) != 0;
            if (activitySecure != expected || dialogSecure != expected) throw new AssertionError("窗口策略不符合预期：" + activitySecure + "/" + dialogSecure);
            // 部分 ROM 默认屏蔽普通 App 的 INFO 日志，测试标记使用 ERROR 级别。
            Log.e("UiProbe", "UI_PROBE_OK secure=" + expected + " activity=" + getClass().getSimpleName());
        });
    }
    @Override public void onDestroy() { if (dialog != null) dialog.dismiss(); super.onDestroy(); }
}

package dev.mocika.shield.loader;

import org.junit.Test;
import static org.junit.Assert.*;

public class MocikaUiTest {
    @Test public void 调试状态未知不能当成关闭且仅限制模式拒绝运行() {
        for (int usb : new int[]{-1, 0, 1}) for (int wifi : new int[]{-1, 0, 1}) {
            int state = MocikaUi.combineAdb(usb, wifi);
            assertEquals(usb == 1 || wifi == 1 ? 1 : usb == 0 && wifi == 0 ? 0 : -1, state);
            assertFalse(MocikaUi.rejectAdb("off", state));
            assertFalse(MocikaUi.rejectAdb("report", state));
            assertEquals(usb != 0 || wifi != 0, MocikaUi.rejectAdb("block", state));
        }
    }
}

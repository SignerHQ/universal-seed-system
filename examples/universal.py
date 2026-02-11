# Copyright (c) 2026 Signer — MIT License

"""Universal Seed System — generate or recover seeds using 256 visual icons."""

import os
import sys
import threading
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PROJECT_DIR)

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QLabel, QScrollArea, QFrame, QListWidget, QListWidgetItem,
    QGridLayout, QPushButton, QProgressBar, QComboBox,
)
from PySide6.QtCore import Qt, QSize, QEvent, QPoint, QRect, Signal, QTimer
from PySide6.QtGui import QPixmap, QIcon, QPainter, QPainterPath, QCursor

from seed import generate_words, get_fingerprint, get_private_key, get_entropy_bits, mouse_entropy, resolve, search, verify_randomness, get_languages
from languages.base import signer_universal_seed_base

ICONS_DIR = os.path.join(PROJECT_DIR, "visuals", "png")
BASE_LOOKUP = {entry[0]: (entry[1], entry[2]) for entry in signer_universal_seed_base}
ICON_SIZE = 36

_icon_cache = {}


def load_icon(index, size=ICON_SIZE):
    key = (index, size)
    if key not in _icon_cache:
        path = os.path.join(ICONS_DIR, f"{index}.png")
        if os.path.exists(path):
            _icon_cache[key] = QPixmap(path).scaled(
                size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation
            )
        else:
            _icon_cache[key] = None
    return _icon_cache[key]


def rounded_pixmap(pm, radius=6):
    out = QPixmap(pm.size())
    out.fill(Qt.transparent)
    p = QPainter(out)
    p.setRenderHint(QPainter.Antialiasing)
    path = QPainterPath()
    path.addRoundedRect(0, 0, pm.width(), pm.height(), radius, radius)
    p.setClipPath(path)
    p.drawPixmap(0, 0, pm)
    p.end()
    return out


# ── Light theme styles ─────────────────────────────────────

STYLE = """
QMainWindow { background: #f5f5f7; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical {
    background: #ececee; width: 6px; border-radius: 3px; margin: 4px 2px;
}
QScrollBar::handle:vertical {
    background: #c0c0c8; border-radius: 3px; min-height: 40px;
}
QScrollBar::handle:vertical:hover { background: #a0a0b0; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QMenu {
    background: #ffffff;
    border: 1px solid #d8d8e0;
    border-radius: 6px;
    padding: 4px;
}
QMenu::item {
    padding: 6px 24px;
    color: #2c2c3a;
    border-radius: 4px;
}
QMenu::item:selected { background: #e8e8f0; }
"""

POPUP_STYLE = """
QListWidget {
    background: #ffffff;
    border: 1px solid #d8d8e0;
    border-radius: 8px;
    padding: 4px;
    outline: none;
    font-size: 13px;
}
QListWidget::item {
    color: #2c2c3a;
    padding: 6px 10px;
    border-radius: 6px;
    margin: 1px 2px;
}
QListWidget::item:hover { background: #f0f0f5; }
QListWidget::item:selected { background: #e8e8f0; color: #1a1a2a; }
QScrollBar:vertical {
    background: transparent; width: 4px; margin: 6px 1px;
}
QScrollBar::handle:vertical {
    background: #c0c0c8; border-radius: 2px; min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""

ICON_PICKER_STYLE = """
QScrollArea {
    background: #ffffff;
    border: 1px solid #d8d8e0;
    border-radius: 10px;
}
QScrollBar:vertical {
    background: transparent; width: 5px; margin: 4px 1px;
}
QScrollBar::handle:vertical {
    background: #c0c0c8; border-radius: 2px; min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""


class SuggestionPopup(QListWidget):
    word_selected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFocusPolicy(Qt.NoFocus)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setMouseTracking(True)  # receive hover events without button press
        self.setIconSize(QSize(24, 24))
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(POPUP_STYLE)
        self.itemClicked.connect(self._on_item_clicked)
        self._filter_installed = False
        self.hide()

    def mouseMoveEvent(self, event):
        """Track hover — highlight item under cursor so Enter/Tab selects it.
        Works around Windows 11 touchpad tap suppression during typing."""
        item = self.itemAt(event.pos())
        if item:
            self.setCurrentItem(item)
        super().mouseMoveEvent(event)

    def show_for(self, suggestions, anchor_widget):
        t0 = time.perf_counter()
        self.clear()
        if not suggestions:
            self.hide()
            return

        # Re-parent to the top-level window so it renders on top of everything
        top = anchor_widget.window()
        if self.parentWidget() is not top:
            self.setParent(top)
            self.setStyleSheet(POPUP_STYLE)

        t1 = time.perf_counter()
        for word, idx in suggestions:
            _, base = BASE_LOOKUP.get(idx, ("?", "?"))
            label = f"[{idx}]  {word}    —  {base}" if word != base else f"[{idx}]  {word}"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, word)
            pm = load_icon(idx, 24)
            if pm:
                item.setIcon(QIcon(pm))
            self.addItem(item)
        t2 = time.perf_counter()

        visible = min(len(suggestions), 7)
        h = max(visible * 36 + 16, 52)
        w = max(anchor_widget.width(), 280)
        self.setFixedSize(w, h)
        pos = anchor_widget.mapTo(top, QPoint(0, anchor_widget.height() + 4))
        self.move(pos)
        self.raise_()
        self.show()
        if not self._filter_installed:
            QApplication.instance().installEventFilter(self)
            self._filter_installed = True
        t3 = time.perf_counter()
        print(f"  [show_for] items={len(suggestions)} setup={(t1-t0)*1000:.2f}ms build={(t2-t1)*1000:.2f}ms layout={(t3-t2)*1000:.2f}ms total={(t3-t0)*1000:.2f}ms")

    def hide(self):
        if self._filter_installed:
            import traceback
            print(f"  [popup.hide] was visible, removing event filter")
            print(f"    caller: {traceback.format_stack()[-2].strip()}")
            QApplication.instance().removeEventFilter(self)
            self._filter_installed = False
        super().hide()

    def _on_item_clicked(self, item):
        t0 = time.perf_counter()
        word = item.data(Qt.UserRole)
        print(f"  [popup._on_item_clicked] word='{word}'")
        if word:
            self.word_selected.emit(word)
        self.hide()
        print(f"  [popup._on_item_clicked] done  ({(time.perf_counter()-t0)*1000:.2f}ms)")

    def eventFilter(self, obj, event):
        """App-level filter: dismiss popup when clicking outside it."""
        if event.type() == QEvent.MouseButtonPress and self.isVisible():
            t0 = time.perf_counter()
            click_pos = event.globalPosition().toPoint()
            popup_rect = QRect(self.mapToGlobal(QPoint(0, 0)), self.size())
            inside = popup_rect.contains(click_pos)
            print(f"  [popup.eventFilter] MouseButtonPress inside={inside} obj={type(obj).__name__}  ({(time.perf_counter()-t0)*1000:.2f}ms)")
            if inside:
                return False  # Let click reach popup items
            self.hide()  # Click outside — just dismiss, no auto-select
            return False
        return False


class IconPickerPopup(QFrame):
    """Grid popup showing all 256 icons for visual selection."""
    icon_selected = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        # No Qt.ToolTip — child widget of the main window
        self.setFocusPolicy(Qt.NoFocus)
        self.setFixedSize(380, 340)
        self._filter_installed = False
        self._anchor = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(ICON_PICKER_STYLE)
        layout.addWidget(scroll)

        container = QWidget()
        container.setStyleSheet("background: #ffffff;")
        grid = QGridLayout(container)
        grid.setContentsMargins(8, 8, 8, 8)
        grid.setSpacing(4)

        cols = 8
        for idx in range(256):
            btn = QLabel()
            btn.setFixedSize(40, 40)
            btn.setAlignment(Qt.AlignCenter)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setProperty("icon_index", idx)
            btn.setStyleSheet(
                "QLabel { background: #f8f8fa; border: 1px solid #e8e8ee; border-radius: 6px; }"
                "QLabel:hover { background: #e8e8f0; border-color: #c0c0d0; }"
            )
            pm = load_icon(idx, 32)
            if pm:
                btn.setPixmap(pm)
            else:
                _, word = BASE_LOOKUP.get(idx, ("?", "?"))
                btn.setText(word[:3])
                btn.setStyleSheet(
                    "QLabel { background: #f8f8fa; border: 1px solid #e8e8ee; border-radius: 6px;"
                    " font-size: 9px; color: #888; }"
                    "QLabel:hover { background: #e8e8f0; border-color: #c0c0d0; }"
                )

            btn.setToolTip(f"{idx}: {BASE_LOOKUP.get(idx, ('?','?'))[1]}")
            btn.installEventFilter(self)
            grid.addWidget(btn, idx // cols, idx % cols)

        scroll.setWidget(container)
        self.hide()

    def eventFilter(self, obj, event):
        # App-level filter: dismiss icon picker when clicking outside it
        if event.type() == QEvent.MouseButtonPress and self.isVisible():
            # Let the anchor widget handle its own toggle
            if obj is self._anchor:
                return False
            if not isinstance(obj, QLabel) or obj.property("icon_index") is None:
                click_pos = event.globalPosition().toPoint()
                picker_rect = QRect(self.mapToGlobal(QPoint(0, 0)), self.size())
                if not picker_rect.contains(click_pos):
                    self.hide()
                    return False
        # Grid icon clicks
        if event.type() == QEvent.MouseButtonRelease and isinstance(obj, QLabel):
            idx = obj.property("icon_index")
            if idx is not None:
                self.icon_selected.emit(idx)
                self.hide()
                return True
        return False

    def show_at(self, anchor_widget):
        self._anchor = anchor_widget
        top = anchor_widget.window()
        if self.parentWidget() is not top:
            self.setParent(top)
        pos = anchor_widget.mapTo(top, QPoint(0, anchor_widget.height() + 4))
        self.move(pos)
        self.raise_()
        self.show()
        if not self._filter_installed:
            QApplication.instance().installEventFilter(self)
            self._filter_installed = True

    def hide(self):
        if self._filter_installed:
            QApplication.instance().removeEventFilter(self)
            self._filter_installed = False
        super().hide()


class SeedWordRow(QFrame):
    status_changed = Signal()

    def __init__(self, position, parent=None):
        super().__init__(parent)
        self.position = position
        self.resolved_index = None
        self._block = False

        self.popup = SuggestionPopup()
        self.popup.word_selected.connect(self._on_word_selected)

        self.icon_picker = IconPickerPopup()
        self.icon_picker.icon_selected.connect(self._on_icon_selected)

        self.setFixedHeight(52)
        self.setStyleSheet(self._style_default())

        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 0, 12, 0)
        lay.setSpacing(12)

        # Position number
        self.pos_label = QLabel(f"{position + 1}")
        self.pos_label.setFixedWidth(24)
        self.pos_label.setAlignment(Qt.AlignCenter)
        self.pos_label.setStyleSheet(
            "color: #9898a8; font-size: 12px; font-weight: 600; border: none; background: none;"
        )
        lay.addWidget(self.pos_label)

        # Icon (clickable)
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(ICON_SIZE, ICON_SIZE)
        self.icon_label.setAlignment(Qt.AlignCenter)
        self.icon_label.setCursor(Qt.PointingHandCursor)
        self.icon_label.installEventFilter(self)
        self._show_placeholder()
        lay.addWidget(self.icon_label)

        # Input
        self.input = QLineEdit()
        self.input.setPlaceholderText("Type a word, emoji, or click icon...")
        self.input.setStyleSheet(
            "QLineEdit { background: transparent; color: #2c2c3a; border: none;"
            " font-size: 14px; padding: 0; selection-background-color: #c0c8e0; }"
        )
        self.input.setMinimumHeight(32)
        lay.addWidget(self.input, 1)

        # Status label
        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.status_label.setFixedWidth(80)
        self.status_label.setStyleSheet(
            "color: #9898a8; font-size: 11px; border: none; background: none;"
        )
        lay.addWidget(self.status_label)

        self.input.textChanged.connect(self._on_text)
        self.input.installEventFilter(self)

    # ── event filter (keyboard nav + icon click) ──────────
    def eventFilter(self, obj, event):
        # Icon label click → open icon picker
        if obj is self.icon_label:
            if event.type() == QEvent.MouseButtonPress:
                if self.icon_picker.isVisible():
                    self.icon_picker.hide()
                else:
                    self.popup.hide()
                    self.icon_picker.show_at(self.icon_label)
                return True
            return False

        if obj is self.input and event.type() == QEvent.FocusIn:
            print(f"  [row{self.position}.eventFilter] FocusIn")
            self.icon_picker.hide()
            return False

        if obj is self.input and event.type() == QEvent.FocusOut:
            reason = event.reason()
            print(f"  [row{self.position}.eventFilter] FocusOut reason={reason.name}")
            if reason == Qt.MouseFocusReason:
                # Delay hide — the click might be landing on the popup
                print(f"    -> delaying hide 150ms (mouse click may be targeting popup)")
                QTimer.singleShot(150, self._deferred_popup_hide)
            else:
                self.popup.hide()
            return False

        if obj is not self.input or event.type() != QEvent.KeyPress:
            return False
        key = event.key()
        if key == Qt.Key_Escape:
            if self.popup.isVisible():
                self.popup.hide()
                return True
            if self.icon_picker.isVisible():
                self.icon_picker.hide()
                return True
        if key == Qt.Key_Down:
            if self.popup.isVisible() and self.popup.count():
                cur = self.popup.currentRow()
                self.popup.setCurrentRow(min(cur + 1, self.popup.count() - 1))
                return True
            self.popup.hide()
            self._focus_next_row()
            return True
        if key == Qt.Key_Up:
            if self.popup.isVisible() and self.popup.count():
                cur = self.popup.currentRow()
                self.popup.setCurrentRow(max(cur - 1, 0))
                return True
            self.popup.hide()
            self._focus_prev_row()
            return True
        if key in (Qt.Key_Return, Qt.Key_Enter):
            if self.popup.isVisible() and self.popup.count():
                # Select highlighted item, or first item if none highlighted
                item = self.popup.currentItem() or self.popup.item(0)
                word = item.data(Qt.UserRole) if item else None
                if word:
                    self.popup.hide()
                    self._on_word_selected(word)
                    self._focus_next_row()
                return True
            # Word resolved — hide popup and move to next row
            self.popup.hide()
            if self.resolved_index is not None:
                self._focus_next_row()
                return True
            return True
        if key == Qt.Key_Tab:
            if self.popup.isVisible() and self.popup.count():
                # Select highlighted item, or first item if none highlighted
                item = self.popup.currentItem() or self.popup.item(0)
                word = item.data(Qt.UserRole) if item else None
                if word:
                    self.popup.hide()
                    self._on_word_selected(word)
                    self._focus_next_row()
                return True
            # No popup — just close and move to next row
            self.popup.hide()
            self._focus_next_row()
            return True
        return False

    def _deferred_popup_hide(self):
        """Hide popup after a short delay — only if input no longer has focus."""
        if not self.input.hasFocus():
            print(f"  [row{self.position}._deferred_popup_hide] input lost focus, hiding popup")
            self.popup.hide()
        else:
            print(f"  [row{self.position}._deferred_popup_hide] input still focused, keeping popup")

    def _focus_next_row(self):
        """Move focus to the next visible row's input field."""
        parent = self.parent()
        if parent is None:
            return
        rows = parent.findChildren(SeedWordRow)
        rows.sort(key=lambda r: r.position)
        for i, r in enumerate(rows):
            if r is self:
                for j in range(i + 1, len(rows)):
                    if rows[j].isVisible():
                        rows[j].input.setFocus()
                        return
                return

    def _focus_prev_row(self):
        """Move focus to the previous visible row's input field."""
        parent = self.parent()
        if parent is None:
            return
        rows = parent.findChildren(SeedWordRow)
        rows.sort(key=lambda r: r.position)
        for i, r in enumerate(rows):
            if r is self:
                for j in range(i - 1, -1, -1):
                    if rows[j].isVisible():
                        rows[j].input.setFocus()
                        return
                return

    # ── styles ───────────────────────────────────────────────
    def _style_default(self):
        return (
            "SeedWordRow { background: #ffffff; border: 1px solid #e4e4ec; border-radius: 10px; }"
        )

    def _style_match(self):
        return (
            "SeedWordRow {"
            " background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #f0faf5, stop:1 #ffffff);"
            " border: 1px solid #b0dcc0; border-radius: 10px; }"
        )

    # ── icon helpers ─────────────────────────────────────────
    def _show_placeholder(self):
        self.icon_label.setPixmap(QPixmap())
        self.icon_label.setText("")
        self.icon_label.setStyleSheet(
            "QLabel { background: #f0f0f5; border: 1px solid #e4e4ec; border-radius: 8px; }"
            "QLabel:hover { background: #e4e4f0; border-color: #c8c8d8; }"
        )

    def _show_icon(self, idx):
        pm = load_icon(idx, ICON_SIZE)
        if pm:
            self.icon_label.setPixmap(rounded_pixmap(pm, 8))
            self.icon_label.setStyleSheet(
                "QLabel { background: #f0faf5; border: 1px solid #b0dcc0; border-radius: 8px; }"
                "QLabel:hover { background: #e0f0ea; border-color: #90c8a8; }"
            )

    def _show_icon_preview(self, idx):
        pm = load_icon(idx, ICON_SIZE)
        if pm:
            self.icon_label.setPixmap(rounded_pixmap(pm, 8))
            self.icon_label.setStyleSheet(
                "QLabel { background: #f8f8fc; border: 1px solid #d0d0e0; border-radius: 8px; }"
                "QLabel:hover { background: #e4e4f0; border-color: #c8c8d8; }"
            )

    # ── resolve + suggest ────────────────────────────────────
    def _resolve_and_display(self, text):
        idx = resolve(text)
        if idx is not None:
            self.resolved_index = idx
            self._show_icon(idx)
            _, base = BASE_LOOKUP.get(idx, ("?", "?"))
            self.status_label.setText(base)
            self.status_label.setStyleSheet(
                "color: #2a9a5a; font-size: 11px; font-weight: 600; border: none; background: none;"
            )
            self.setStyleSheet(self._style_match())
        else:
            self.resolved_index = None
            self._show_placeholder()
            self.status_label.setText("")
            self.status_label.setStyleSheet(
                "color: #9898a8; font-size: 11px; border: none; background: none;"
            )
            self.setStyleSheet(self._style_default())
        self.status_changed.emit()
        return idx

    def _on_text(self, raw):
        if self._block:
            return
        t_start = time.perf_counter()
        text = raw.strip()
        if not text:
            self.resolved_index = None
            self._show_placeholder()
            self.status_label.setText("")
            self.status_label.setStyleSheet(
                "color: #9898a8; font-size: 11px; border: none; background: none;"
            )
            self.setStyleSheet(self._style_default())
            self.popup.hide()
            self.status_changed.emit()
            return

        t0 = time.perf_counter()
        idx = self._resolve_and_display(text)
        t1 = time.perf_counter()

        # Show suggestions while typing
        results = search(text, 8)
        t2 = time.perf_counter()

        # Hide if only 1 suggestion and it matches the input exactly
        if len(results) == 1 and results[0][0] == text.lower():
            self.popup.hide()
        elif results:
            self.popup.show_for(results, self.input)
        else:
            self.popup.hide()
        t3 = time.perf_counter()

        # Preview the first suggestion's icon (what Tab would select)
        if idx is None and results:
            preview_idx = results[0][1]
            self._show_icon_preview(preview_idx)
            _, base = BASE_LOOKUP.get(preview_idx, ("?", "?"))
            self.status_label.setText(base)
            self.status_label.setStyleSheet(
                "color: #9898a8; font-size: 11px; font-style: italic;"
                " border: none; background: none;"
            )
        t_end = time.perf_counter()
        print(f"[row{self.position}._on_text] '{text}' resolve={(t1-t0)*1000:.2f}ms search={(t2-t1)*1000:.2f}ms popup={(t3-t2)*1000:.2f}ms total={(t_end-t_start)*1000:.2f}ms")

    def _on_word_selected(self, word):
        t0 = time.perf_counter()
        print(f"  [row{self.position}._on_word_selected] word='{word}'")
        self._block = True
        self.input.setText(word)
        self._block = False
        self._resolve_and_display(word)
        self.popup.hide()
        self.input.setFocus()
        print(f"  [row{self.position}._on_word_selected] done  ({(time.perf_counter()-t0)*1000:.2f}ms)")

    def clear(self):
        """Reset this row to its empty state."""
        self._block = True
        self.input.clear()
        self._block = False
        self.resolved_index = None
        self._show_placeholder()
        self.status_label.setText("")
        self.status_label.setStyleSheet(
            "color: #9898a8; font-size: 11px; border: none; background: none;"
        )
        self.setStyleSheet(self._style_default())
        self.popup.hide()
        self.icon_picker.hide()
        self.status_changed.emit()

    def _on_icon_selected(self, idx):
        """Called when an icon is picked from the icon picker grid."""
        _, base = BASE_LOOKUP.get(idx, ("?", "?"))
        self._block = True
        self.input.setText(base)
        self._block = False
        self.resolved_index = idx
        self._show_icon(idx)
        self.status_label.setText(base)
        self.status_label.setStyleSheet(
            "color: #2a9a5a; font-size: 11px; font-weight: 600; border: none; background: none;"
        )
        self.setStyleSheet(self._style_match())
        self.status_changed.emit()
        self.input.setFocus()


TOGGLE_ACTIVE = (
    "QPushButton { background: #2c2c3a; color: #ffffff; border: none;"
    " border-radius: 10px; font-size: 12px; font-weight: 600; padding: 4px 14px; }"
)
TOGGLE_INACTIVE = (
    "QPushButton { background: #e8e8f0; color: #6a6a80; border: none;"
    " border-radius: 10px; font-size: 12px; font-weight: 500; padding: 4px 14px; }"
    "QPushButton:hover { background: #dcdce8; }"
)
GENERATE_BTN = (
    "QPushButton { background: #2a9a5a; color: #ffffff; border: none;"
    " border-radius: 10px; font-size: 13px; font-weight: 600; padding: 6px 20px; }"
    "QPushButton:hover { background: #23884e; }"
    "QPushButton:pressed { background: #1d7542; }"
)
SMALL_BTN = (
    "QPushButton { background: #e8e8f0; color: #6a6a80; border: none;"
    " border-radius: 10px; font-size: 11px; font-weight: 500; padding: 4px 10px; }"
    "QPushButton:hover { background: #dcdce8; }"
)


class SeedTestWindow(QMainWindow):
    _key_ready = Signal(str, str)  # (key_hex, fingerprint)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Universal Seed System")
        self.setMinimumSize(620, 600)
        self.resize(640, 820)
        self.setStyleSheet(STYLE)
        self.word_count = 36
        self._base_indexes = None  # Original indexes before passphrase transform
        self._key_version = 0  # Tracks async key derivation freshness
        self._key_deriving = False  # True while a thread is running
        self._full_key_hex = ""  # Full derived key hex for copy
        self._key_ready.connect(self._on_key_ready)
        self._key_timer = QTimer()
        self._key_timer.setSingleShot(True)
        self._key_timer.setInterval(400)
        self._key_timer.timeout.connect(self._start_key_derivation)

        central = QWidget()
        central.setStyleSheet("background: #f5f5f7;")
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(20, 16, 20, 16)
        main_layout.setSpacing(0)

        # Header
        header = QWidget()
        header.setStyleSheet("background: transparent;")
        hl = QVBoxLayout(header)
        hl.setContentsMargins(0, 0, 0, 12)
        hl.setSpacing(4)

        title = QLabel("Universal Seed System")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            "color: #1a1a2a; font-size: 22px; font-weight: 700; letter-spacing: 1px;"
        )
        hl.addWidget(title)

        subtitle = QLabel("Generate a new seed or recover an existing one")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #8888a0; font-size: 12px;")
        hl.addWidget(subtitle)
        main_layout.addWidget(header)

        # Mouse entropy collection (shown first so users collect before generating)
        self._mouse_pool = mouse_entropy()
        self._collecting_mouse = False

        mouse_frame = QFrame()
        mouse_frame.setFixedHeight(54)
        mouse_frame.setStyleSheet(
            "QFrame { background: #fef0ef; border: 1px solid #e8b0a8; border-radius: 10px; }"
        )
        mouse_vlay = QVBoxLayout(mouse_frame)
        mouse_vlay.setContentsMargins(16, 8, 16, 8)
        mouse_vlay.setSpacing(6)

        mouse_row = QHBoxLayout()
        mouse_row.setSpacing(10)

        mouse_icon = QLabel("\U0001f5b1")
        mouse_icon.setFixedWidth(20)
        mouse_icon.setStyleSheet("font-size: 14px; border: none; background: none;")
        mouse_row.addWidget(mouse_icon)

        self.mouse_label = QLabel("Collect mouse movement (increases randomness)")
        self.mouse_label.setStyleSheet(
            "color: #c04030; font-size: 12px; border: none; background: none;"
        )
        mouse_row.addWidget(self.mouse_label, 1)

        self.mouse_clear_btn = QPushButton("Clear")
        self.mouse_clear_btn.setFixedSize(50, 24)
        self.mouse_clear_btn.setCursor(Qt.PointingHandCursor)
        self.mouse_clear_btn.setStyleSheet(
            "QPushButton { background: #e8e8f0; color: #6a6a80; border: none;"
            " border-radius: 8px; font-size: 11px; font-weight: 500; }"
            "QPushButton:hover { background: #dcdce8; }"
        )
        self.mouse_clear_btn.clicked.connect(self._clear_mouse)
        mouse_row.addWidget(self.mouse_clear_btn)

        self.mouse_btn = QPushButton("Collect")
        self.mouse_btn.setFixedSize(70, 24)
        self.mouse_btn.setCursor(Qt.PointingHandCursor)
        self.mouse_btn.setStyleSheet(
            "QPushButton { background: #e8e8f0; color: #6a6a80; border: none;"
            " border-radius: 8px; font-size: 11px; font-weight: 500; }"
            "QPushButton:hover { background: #dcdce8; }"
        )
        self.mouse_btn.clicked.connect(self._toggle_mouse_collection)
        mouse_row.addWidget(self.mouse_btn)

        mouse_vlay.addLayout(mouse_row)

        self.mouse_progress = QProgressBar()
        self.mouse_progress.setFixedHeight(3)
        self.mouse_progress.setRange(0, 256)
        self.mouse_progress.setValue(0)
        self.mouse_progress.setTextVisible(False)
        self.mouse_progress.setStyleSheet(
            "QProgressBar { background: #e8e8f0; border: none; border-radius: 1px; }"
            "QProgressBar::chunk { background: #e85040; border-radius: 1px; }"
        )
        mouse_vlay.addWidget(self.mouse_progress)

        self._mouse_timer = QTimer()
        self._mouse_timer.setInterval(16)
        self._mouse_timer.timeout.connect(self._poll_mouse)

        self.mouse_frame = mouse_frame
        main_layout.addSpacing(4)
        main_layout.addWidget(mouse_frame)
        main_layout.addSpacing(8)

        # Controls row 1: [16] [32]  [Copy] [Paste] [Clear]
        controls = QHBoxLayout()
        controls.setContentsMargins(0, 0, 0, 0)
        controls.setSpacing(6)

        self.btn_24 = QPushButton("24 words")
        self.btn_24.setFixedHeight(28)
        self.btn_24.setCursor(Qt.PointingHandCursor)
        self.btn_24.setStyleSheet(TOGGLE_INACTIVE)
        self.btn_24.clicked.connect(lambda: self._set_word_count(24))
        controls.addWidget(self.btn_24)

        self.btn_36 = QPushButton("36 words")
        self.btn_36.setFixedHeight(28)
        self.btn_36.setCursor(Qt.PointingHandCursor)
        self.btn_36.setStyleSheet(TOGGLE_ACTIVE)
        self.btn_36.clicked.connect(lambda: self._set_word_count(36))
        controls.addWidget(self.btn_36)

        controls.addSpacing(8)

        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setFixedHeight(28)
        self.copy_btn.setCursor(Qt.PointingHandCursor)
        self.copy_btn.setStyleSheet(SMALL_BTN)
        self.copy_btn.clicked.connect(self._copy_seed)
        controls.addWidget(self.copy_btn)

        paste_btn = QPushButton("Paste")
        paste_btn.setFixedHeight(28)
        paste_btn.setCursor(Qt.PointingHandCursor)
        paste_btn.setStyleSheet(SMALL_BTN)
        paste_btn.clicked.connect(self._paste_seed)
        controls.addWidget(paste_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedHeight(28)
        clear_btn.setCursor(Qt.PointingHandCursor)
        clear_btn.setStyleSheet(SMALL_BTN)
        clear_btn.clicked.connect(self._clear_all)
        controls.addWidget(clear_btn)

        controls.addStretch()

        self.lang_combo = QComboBox()
        self.lang_combo.setFixedSize(130, 28)
        self.lang_combo.setCursor(Qt.PointingHandCursor)
        self.lang_combo.setStyleSheet(
            "QComboBox { background: #e8e8f0; color: #6a6a80; border: none;"
            " border-radius: 10px; font-size: 12px; font-weight: 500; padding: 4px 10px; }"
            "QComboBox:hover { background: #dcdce8; }"
            "QComboBox::drop-down { border: none; }"
            "QComboBox::down-arrow { image: none; }"
        )
        for code, label in get_languages():
            self.lang_combo.addItem(label, code)
        self.lang_combo.currentIndexChanged.connect(self._on_language_changed)
        controls.addWidget(self.lang_combo)

        self.generate_btn = QPushButton("Generate")
        self.generate_btn.setMinimumWidth(100)
        self.generate_btn.setFixedHeight(28)
        self.generate_btn.setCursor(Qt.PointingHandCursor)
        self.generate_btn.setStyleSheet(GENERATE_BTN)
        self.generate_btn.clicked.connect(self._generate_seed)
        controls.addWidget(self.generate_btn)

        main_layout.addLayout(controls)
        main_layout.addSpacing(8)

        # Scroll
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        main_layout.addWidget(scroll, 1)

        container = QWidget()
        container.setStyleSheet("background: transparent;")
        rows_layout = QVBoxLayout(container)
        rows_layout.setContentsMargins(0, 0, 4, 0)
        rows_layout.setSpacing(4)

        self.rows = []
        for i in range(36):
            row = SeedWordRow(i)
            row.status_changed.connect(self._update_status)
            rows_layout.addWidget(row)
            self.rows.append(row)

        rows_layout.addStretch()
        scroll.setWidget(container)

        # Hide popups when app loses focus (minimize, alt+tab, etc.)
        QApplication.instance().applicationStateChanged.connect(self._on_app_state)

        # Passphrase (optional second factor)
        pp_frame = QFrame()
        pp_frame.setFixedHeight(44)
        pp_frame.setStyleSheet(
            "QFrame { background: #ffffff; border: 1px solid #e4e4ec; border-radius: 10px; }"
        )
        pp_lay = QHBoxLayout(pp_frame)
        pp_lay.setContentsMargins(16, 0, 16, 0)
        pp_lay.setSpacing(10)

        pp_icon = QLabel("\U0001f512")
        pp_icon.setFixedWidth(20)
        pp_icon.setStyleSheet("font-size: 14px; border: none; background: none;")
        pp_lay.addWidget(pp_icon)

        self.passphrase_input = QLineEdit()
        self.passphrase_input.setPlaceholderText("Passphrase (optional)")
        self.passphrase_input.setEchoMode(QLineEdit.Password)
        self.passphrase_input.setStyleSheet(
            "QLineEdit { background: transparent; color: #2c2c3a; border: none;"
            " font-size: 13px; padding: 0; selection-background-color: #c0c8e0; }"
        )
        pp_lay.addWidget(self.passphrase_input, 1)

        self.pp_toggle = QPushButton("Show")
        self.pp_toggle.setFixedSize(50, 24)
        self.pp_toggle.setCursor(Qt.PointingHandCursor)
        self.pp_toggle.setStyleSheet(
            "QPushButton { background: #e8e8f0; color: #6a6a80; border: none;"
            " border-radius: 8px; font-size: 11px; font-weight: 500; }"
            "QPushButton:hover { background: #dcdce8; }"
        )
        self.pp_toggle.clicked.connect(self._toggle_passphrase)
        pp_lay.addWidget(self.pp_toggle)

        # Entropy label updates instantly; row transforms debounce 150ms
        self._pp_timer = QTimer()
        self._pp_timer.setSingleShot(True)
        self._pp_timer.setInterval(150)
        self._pp_timer.timeout.connect(self._apply_passphrase)
        self.passphrase_input.textChanged.connect(self._on_passphrase_key)

        main_layout.addSpacing(8)
        main_layout.addWidget(pp_frame)

        pp_warn = QLabel("If you set a passphrase, you must remember it — losing it means losing access to your seed.")
        pp_warn.setWordWrap(True)
        pp_warn.setStyleSheet(
            "color: #b08030; font-size: 10px; font-style: italic;"
            " background: none; padding: 0 4px;"
        )
        main_layout.addWidget(pp_warn)

        # Status bar
        self.status_frame = QFrame()
        self.status_frame.setFixedHeight(44)
        self.status_frame.setStyleSheet(
            "QFrame { background: #ffffff; border: 1px solid #e4e4ec; border-radius: 10px; }"
        )
        sl = QHBoxLayout(self.status_frame)
        sl.setContentsMargins(16, 0, 16, 0)

        self.count_label = QLabel("0 / 36")
        self.count_label.setStyleSheet(
            "color: #9898a8; font-size: 14px; font-weight: 600; border: none; background: none;"
        )
        sl.addWidget(self.count_label)

        self.hint_label = QLabel("words resolved")
        self.hint_label.setStyleSheet(
            "color: #b0b0c0; font-size: 12px; border: none; background: none;"
        )
        sl.addWidget(self.hint_label)

        # Bit-strength indicator (shown next to "seed complete")
        self.bits_label = QLabel("")
        self.bits_label.setStyleSheet(
            "color: #b0b0c0; font-size: 11px; font-weight: 600; border: none; background: none;"
        )
        sl.addWidget(self.bits_label)

        sl.addStretch()

        # Fingerprint — external checksum the user writes down alongside their seed
        self.fp_label = QLabel("")
        self.fp_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.fp_label.setStyleSheet(
            "color: #b0b0c0; font-size: 15px; font-weight: 700;"
            " font-family: monospace; letter-spacing: 3px;"
            " border: none; background: none;"
        )
        sl.addWidget(self.fp_label)

        main_layout.addSpacing(8)
        main_layout.addWidget(self.status_frame)

        # Derived key display: [Private seed:  hex...hex  [Copy]]
        key_row = QHBoxLayout()
        key_row.setContentsMargins(0, 0, 0, 0)
        key_row.setSpacing(6)
        key_row.addStretch()

        self.key_prefix = QLabel("private seed:")
        self.key_prefix.setStyleSheet(
            "color: #9898a8; font-size: 10px; font-family: monospace;"
            " background: none;"
        )
        self.key_prefix.hide()
        key_row.addWidget(self.key_prefix)

        self.key_label = QLabel("")
        self.key_label.setStyleSheet(
            "color: #9898a8; font-size: 10px; font-family: monospace;"
            " background: none; padding: 2px 0;"
        )
        self.key_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        key_row.addWidget(self.key_label)

        self.key_copy_btn = QPushButton("Copy")
        self.key_copy_btn.setFixedSize(40, 18)
        self.key_copy_btn.setCursor(Qt.PointingHandCursor)
        self.key_copy_btn.setStyleSheet(
            "QPushButton { background: #e8e8f0; color: #6a6a80; border: none;"
            " border-radius: 6px; font-size: 9px; font-weight: 500; }"
            "QPushButton:hover { background: #dcdce8; }"
        )
        self.key_copy_btn.clicked.connect(self._copy_private_seed)
        self.key_copy_btn.hide()
        key_row.addWidget(self.key_copy_btn)

        key_row.addStretch()
        main_layout.addLayout(key_row)

        # Verify randomness button (bottom-left)
        bottom_row = QHBoxLayout()
        bottom_row.setContentsMargins(0, 0, 0, 0)

        self.verify_btn = QPushButton("Verify Randomness")
        self.verify_btn.setFixedHeight(22)
        self.verify_btn.setCursor(Qt.PointingHandCursor)
        self.verify_btn.setStyleSheet(
            "QPushButton { background: none; color: #9898a8; border: none;"
            " font-size: 10px; font-weight: 500; padding: 0 4px; }"
            "QPushButton:hover { color: #6a6a80; text-decoration: underline; }"
        )
        self.verify_btn.clicked.connect(self._open_randomness_dialog)
        bottom_row.addWidget(self.verify_btn)
        bottom_row.addStretch()

        main_layout.addSpacing(2)
        main_layout.addLayout(bottom_row)

    def _open_randomness_dialog(self):
        if hasattr(self, '_randomness_dialog') and self._randomness_dialog and self._randomness_dialog.isVisible():
            self._randomness_dialog.raise_()
            self._randomness_dialog.activateWindow()
            return
        self._randomness_dialog = RandomnessDialog()
        self._randomness_dialog.show()

    # ── copy / paste / clear ────────────────────────────────
    def _flash_copied(self, btn):
        """Temporarily show 'Copied!' feedback on a button."""
        orig_text = btn.text()
        orig_style = btn.styleSheet()
        btn.setText("Copied!")
        btn.setStyleSheet(
            "QPushButton { background: #d0f0d8; color: #2a9a5a; border: none;"
            " border-radius: 8px; font-size: 11px; font-weight: 600; }"
            "QPushButton:hover { background: #c0e8cc; }"
        )
        QTimer.singleShot(1200, lambda: (btn.setText(orig_text), btn.setStyleSheet(orig_style)))

    def _copy_seed(self):
        """Copy all visible resolved words to clipboard, space-separated."""
        words = []
        for row in self.rows[:self.word_count]:
            text = row.input.text().strip()
            if text:
                words.append(text)
        if words:
            QApplication.clipboard().setText(" ".join(words))
            self._flash_copied(self.copy_btn)

    def _copy_private_seed(self):
        """Copy the full derived key hex to clipboard."""
        if self._full_key_hex:
            QApplication.clipboard().setText(self._full_key_hex)
            self._flash_copied(self.key_copy_btn)

    def _paste_seed(self):
        """Paste words from clipboard into rows (space/newline/comma separated)."""
        text = QApplication.clipboard().text()
        if not text:
            return
        import re
        words = re.split(r"[\s,]+", text.strip())
        words = [w for w in words if w]
        n = min(len(words), self.word_count)
        for i in range(n):
            row = self.rows[i]
            row._block = True
            row.input.setText(words[i])
            row._block = False
            row._resolve_and_display(words[i])
        # Clear passphrase so pasted words display as-is
        # (avoids double-transforming already-transformed words)
        self.passphrase_input.clear()
        # Pasted words are the new base seed
        active = self.rows[:self.word_count]
        resolved = [r.resolved_index for r in active if r.resolved_index is not None]
        if len(resolved) == self.word_count:
            self._base_indexes = resolved
        else:
            self._base_indexes = None
        self._update_status()
        self.rows[0].input.setFocus()

    def _clear_all(self):
        """Clear all rows and reset state."""
        self._base_indexes = None
        for row in self.rows:
            row.clear()
        self.passphrase_input.clear()
        self._update_status()

    # ── passphrase toggle ──────────────────────────────────
    def _toggle_passphrase(self):
        if self.passphrase_input.echoMode() == QLineEdit.Password:
            self.passphrase_input.setEchoMode(QLineEdit.Normal)
            self.pp_toggle.setText("Hide")
        else:
            self.passphrase_input.setEchoMode(QLineEdit.Password)
            self.pp_toggle.setText("Show")

    # ── passphrase handling ─────────────────────────────────
    def _on_passphrase_key(self):
        """Called on every keystroke — updates entropy instantly, debounces key derivation."""
        pp = self.passphrase_input.text()
        # Instant: update entropy label (no widget churn)
        active = self.rows[:self.word_count]
        n = sum(1 for r in active if r.resolved_index is not None)
        if n == self.word_count:
            bits = get_entropy_bits(self.word_count, pp)
            bits_str = f"{bits:.0f}-bit entropy" if bits == int(bits) else f"~{bits:.0f}-bit entropy"
            self.bits_label.setText(bits_str)
        # Debounce: key derivation + fingerprint after typing pause
        self._pp_timer.start()

    def _apply_passphrase(self):
        """Update key display + fingerprint — runs after 150ms typing pause."""
        self._update_status()

    # ── mouse entropy collection ─────────────────────────
    def _mouse_style_for_count(self, count):
        """Return (chunk_color, text_color, frame_bg, frame_border) based on count."""
        if count >= 192:
            return ("#2a9a5a", "#2a8a4a", "#f0faf5", "#b0dcc0")
        elif count >= 128:
            return ("#c0c020", "#908a10", "#fdfdf0", "#d8d8a0")
        elif count >= 64:
            return ("#e8a040", "#b08030", "#fff8f0", "#e8c090")
        else:
            return ("#e85040", "#c04030", "#fef0ef", "#e8b0a8")

    def _apply_mouse_style(self, count):
        """Apply mouse entropy colors based on current count."""
        chunk, text, frame_bg, frame_border = self._mouse_style_for_count(count)
        self.mouse_progress.setStyleSheet(
            f"QProgressBar {{ background: #e8e8f0; border: none; border-radius: 1px; }}"
            f"QProgressBar::chunk {{ background: {chunk}; border-radius: 1px; }}"
        )
        self.mouse_frame.setStyleSheet(
            f"QFrame {{ background: {frame_bg}; border: 1px solid {frame_border}; border-radius: 10px; }}"
        )
        return chunk, text, frame_bg, frame_border

    def _clear_mouse(self):
        """Clear collected mouse entropy and reset UI."""
        if self._collecting_mouse:
            self._stop_mouse_collection()
        self._mouse_pool.reset()
        self.mouse_label.setText("Collect mouse movement (increases randomness)")
        self.mouse_label.setStyleSheet(
            "color: #c04030; font-size: 12px; border: none; background: none;"
        )
        self.mouse_progress.setValue(0)
        self._apply_mouse_style(0)

    def _toggle_mouse_collection(self):
        if self._collecting_mouse:
            self._stop_mouse_collection()
        else:
            self._start_mouse_collection()

    def _start_mouse_collection(self):
        self._collecting_mouse = True
        count = self._mouse_pool.sample_count
        self.mouse_btn.setText("Stop")
        self.mouse_btn.setStyleSheet(
            "QPushButton { background: #e8524a; color: #ffffff; border: none;"
            " border-radius: 8px; font-size: 11px; font-weight: 600; }"
            "QPushButton:hover { background: #d4443c; }"
        )
        if count > 0:
            self.mouse_label.setText(f"{count} movements — move your mouse around")
        else:
            self.mouse_label.setText("Move your mouse around")
        _, text_color, _, _ = self._mouse_style_for_count(count)
        self.mouse_label.setStyleSheet(
            f"color: {text_color}; font-size: 12px; font-weight: 500;"
            " border: none; background: none;"
        )
        self.mouse_progress.setValue(min(count, 256))
        self._apply_mouse_style(count)
        # Poll global cursor position at ~60fps (works outside the window)
        self._mouse_timer.start()

    def _stop_mouse_collection(self):
        self._collecting_mouse = False
        self._mouse_timer.stop()
        count = self._mouse_pool.sample_count
        self.mouse_btn.setText("Collect")
        self.mouse_btn.setStyleSheet(
            "QPushButton { background: #e8e8f0; color: #6a6a80; border: none;"
            " border-radius: 8px; font-size: 11px; font-weight: 500; }"
            "QPushButton:hover { background: #dcdce8; }"
        )
        _, text_color, _, _ = self._mouse_style_for_count(count)
        if count > 0:
            self.mouse_label.setText(f"{count} movements collected")
            self.mouse_label.setStyleSheet(
                f"color: {text_color}; font-size: 12px; font-weight: 600;"
                " border: none; background: none;"
            )
        else:
            self.mouse_label.setText("Collect mouse movement (increases randomness)")
            self.mouse_label.setStyleSheet(
                f"color: {text_color}; font-size: 12px; border: none; background: none;"
            )
        self._apply_mouse_style(count)

    def _poll_mouse(self):
        """Poll global cursor position — works even outside the window."""
        pos = QCursor.pos()
        if not self._mouse_pool.add_sample(pos.x(), pos.y()):
            return  # No movement — skip
        count = self._mouse_pool.sample_count
        self.mouse_label.setText(f"{count} movements collected")
        self.mouse_progress.setValue(min(count, 256))
        # Update colors at threshold crossings (64, 128, 192)
        if count in (64, 128, 192, 256):
            _, text_color, _, _ = self._apply_mouse_style(count)
            self.mouse_label.setStyleSheet(
                f"color: {text_color}; font-size: 12px; font-weight: 500;"
                " border: none; background: none;"
            )

    # ── word count toggle ─────────────────────────────────
    def _set_word_count(self, count):
        if count == self.word_count:
            return
        self.word_count = count
        # Update toggle styles
        self.btn_24.setStyleSheet(TOGGLE_ACTIVE if count == 24 else TOGGLE_INACTIVE)
        self.btn_36.setStyleSheet(TOGGLE_ACTIVE if count == 36 else TOGGLE_INACTIVE)
        # Show/hide rows — keep data intact so switching back restores words
        for i, row in enumerate(self.rows):
            if i < count:
                row.show()
            else:
                row.hide()
        self._update_status()

    # ── language change ─────────────────────────────────────
    def _on_language_changed(self, index):
        """Auto-regenerate the seed when the user picks a different language."""
        if self._base_indexes is not None:
            self._generate_seed()

    # ── generate seed ─────────────────────────────────────
    def _generate_seed(self):
        # Mix in mouse entropy if collected
        extra = self._mouse_pool.digest() if self._mouse_pool.sample_count > 0 else None
        lang_code = self.lang_combo.currentData()
        language = lang_code if lang_code != "english" else None
        seed = list(generate_words(self.word_count, extra_entropy=extra, language=language))
        self._base_indexes = [idx for idx, word in seed]

        # Display the words (use translated word from seed, not BASE_LOOKUP)
        for i, (idx, word) in enumerate(seed):
            row = self.rows[i]
            row._block = True
            row.input.setText(word)
            row._block = False
            row._resolve_and_display(word)
        self._update_status()
        self.rows[0].input.setFocus()

    # ── status ────────────────────────────────────────────
    def _update_status(self):
        active = self.rows[:self.word_count]
        n = sum(1 for r in active if r.resolved_index is not None)
        total = self.word_count
        self.count_label.setText(f"{n} / {total}")

        if n == total:
            indexes = [r.resolved_index for r in active]
            # Capture base indexes when seed first completes
            if self._base_indexes is None:
                self._base_indexes = list(indexes)
            pp = self.passphrase_input.text()
            # Fast fingerprint (HMAC only, no passphrase — instant)
            fp = get_fingerprint(indexes)
            bits = get_entropy_bits(self.word_count, pp)
            bits_str = f"{bits:.0f}-bit entropy" if bits == int(bits) else f"~{bits:.0f}-bit entropy"
            self.count_label.setStyleSheet(
                "color: #2a9a5a; font-size: 14px; font-weight: 700;"
                " border: none; background: none;"
            )
            self.hint_label.setText("seed complete")
            self.hint_label.setStyleSheet(
                "color: #2a9a5a; font-size: 12px; font-weight: 600;"
                " border: none; background: none;"
            )
            self.bits_label.setText(bits_str)
            self.bits_label.setStyleSheet(
                "color: #2a9a5a; font-size: 11px; font-weight: 600;"
                " border: none; background: none;"
            )
            self.fp_label.setText(fp)
            self.fp_label.setStyleSheet(
                "color: #2a9a5a; font-size: 15px; font-weight: 700;"
                " font-family: monospace; letter-spacing: 3px;"
                " border: none; background: none;"
            )
            self.status_frame.setStyleSheet(
                "QFrame { background: #f0faf5; border: 1px solid #b0dcc0;"
                " border-radius: 10px; }"
            )
            # Schedule key derivation (debounced — avoids CPU flood on rapid clicks)
            self._key_version += 1
            self._key_indexes = list(indexes)
            self._key_passphrase = pp
            self.key_label.setText("deriving key...")
            self.key_label.setStyleSheet(
                "color: #9898a8; font-size: 10px; font-family: monospace;"
                " background: none; padding: 2px 4px;"
            )
            self._key_timer.start()
        else:
            self.count_label.setStyleSheet(
                f"color: {'#5a5a70' if n else '#9898a8'}; font-size: 14px; "
                "font-weight: 600; border: none; background: none;"
            )
            self.hint_label.setText("words resolved")
            self.hint_label.setStyleSheet(
                "color: #b0b0c0; font-size: 12px; border: none; background: none;"
            )
            self.bits_label.setText("")
            self.bits_label.setStyleSheet(
                "color: #b0b0c0; font-size: 11px; font-weight: 600;"
                " border: none; background: none;"
            )
            self.fp_label.setText("")
            self.fp_label.setStyleSheet(
                "color: #b0b0c0; font-size: 15px; font-weight: 700;"
                " font-family: monospace; letter-spacing: 3px;"
                " border: none; background: none;"
            )
            self.status_frame.setStyleSheet(
                "QFrame { background: #ffffff; border: 1px solid #e4e4ec;"
                " border-radius: 10px; }"
            )
            self.key_label.setText("")
            self.key_prefix.hide()
            self.key_copy_btn.hide()
            self._full_key_hex = ""

    def _start_key_derivation(self):
        """Spawn one background thread for key derivation (debounced)."""
        if self._key_deriving:
            self._key_timer.start()  # retry after current one finishes
            return
        idxs = getattr(self, '_key_indexes', None)
        pp = getattr(self, '_key_passphrase', '')
        if idxs is None:
            return
        self._key_deriving = True
        version = self._key_version
        def _derive():
            key_bytes = get_private_key(idxs, pp)
            fp2 = get_fingerprint(idxs, pp)
            self._key_deriving = False
            if self._key_version == version:
                self._key_ready.emit(key_bytes.hex(), fp2)
        threading.Thread(target=_derive, daemon=True).start()

    def _on_key_ready(self, key_hex, fp):
        """Called from signal when background key derivation completes."""
        self._full_key_hex = key_hex
        self.key_label.setText(f"{key_hex[:16]}...{key_hex[-16:]}")
        self.key_label.setStyleSheet(
            "color: #6a6a80; font-size: 10px; font-family: monospace;"
            " background: none; padding: 2px 0;"
        )
        self.key_prefix.show()
        self.key_copy_btn.show()
        self.fp_label.setText(fp)

    def _hide_all_popups(self, reason="unknown"):
        print(f"  [window._hide_all_popups] reason={reason}")
        for row in self.rows:
            row.popup.hide()
            row.icon_picker.hide()

    def _on_app_state(self, state):
        if state != Qt.ApplicationActive:
            self._hide_all_popups(reason=f"app_state={state}")

    def changeEvent(self, event):
        if event.type() in (QEvent.WindowDeactivate, QEvent.WindowStateChange):
            self._hide_all_popups(reason=f"changeEvent={event.type().name}")
        super().changeEvent(event)

    def hideEvent(self, event):
        self._hide_all_popups(reason="hideEvent")
        super().hideEvent(event)

    def moveEvent(self, event):
        self._hide_all_popups(reason="moveEvent")
        super().moveEvent(event)


RANDOMNESS_DIALOG_STYLE = """
QDialog { background: #f5f5f7; }
"""

RANDOMNESS_TEST_LABEL = (
    "color: #9898a8; font-size: 13px; font-weight: 500;"
    " background: none; border: none;"
)
RANDOMNESS_TEST_PASS = (
    "color: #2a9a5a; font-size: 13px; font-weight: 600;"
    " background: none; border: none;"
)
RANDOMNESS_TEST_FAIL = (
    "color: #d04040; font-size: 13px; font-weight: 600;"
    " background: none; border: none;"
)


# Friendly display names for each test
_TEST_DISPLAY_NAMES = {
    "monobit": "Bit Balance",
    "chi_squared": "Byte Frequency",
    "runs": "Bit Runs",
    "autocorrelation": "Autocorrelation",
}

# Short descriptions for each test
_TEST_DESCRIPTIONS = {
    "monobit": "Checks if 0s and 1s are roughly 50/50",
    "chi_squared": "Checks if all 256 byte values appear uniformly",
    "runs": "Detects stuck patterns or predictable sequences",
    "autocorrelation": "Checks for correlations between bit positions",
}


class RandomnessDialog(QMainWindow):
    """Window that runs randomness verification with a progress bar."""
    _result_ready = Signal(object)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Randomness Verification")
        self.setFixedSize(420, 360)
        self.setStyleSheet(RANDOMNESS_DIALOG_STYLE)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(0)

        # Title
        title = QLabel("Randomness Verification")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            "color: #1a1a2a; font-size: 18px; font-weight: 700;"
            " letter-spacing: 0.5px; background: none; border: none;"
        )
        layout.addWidget(title)

        subtitle = QLabel("Testing entropy source quality")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet(
            "color: #8888a0; font-size: 12px; background: none; border: none;"
        )
        layout.addWidget(subtitle)
        layout.addSpacing(16)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setFixedHeight(6)
        self.progress.setRange(0, 0)  # indeterminate
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet(
            "QProgressBar { background: #e8e8f0; border: none; border-radius: 3px; }"
            "QProgressBar::chunk { background: #2a9a5a; border-radius: 3px; }"
        )
        layout.addWidget(self.progress)
        layout.addSpacing(6)

        self.status_label = QLabel("Collecting entropy samples...")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet(
            "color: #9898a8; font-size: 11px; background: none; border: none;"
        )
        layout.addWidget(self.status_label)
        layout.addSpacing(16)

        # Test result rows (initially hidden)
        test_names = ["monobit", "chi_squared", "runs", "autocorrelation"]
        self._test_rows = {}

        tests_frame = QFrame()
        tests_frame.setStyleSheet(
            "QFrame { background: #ffffff; border: 1px solid #e4e4ec; border-radius: 10px; }"
        )
        tests_layout = QVBoxLayout(tests_frame)
        tests_layout.setContentsMargins(16, 12, 16, 12)
        tests_layout.setSpacing(8)

        for name in test_names:
            row = QHBoxLayout()
            row.setSpacing(10)

            icon_label = QLabel("")
            icon_label.setFixedWidth(24)
            icon_label.setAlignment(Qt.AlignCenter)
            icon_label.setStyleSheet(
                "font-size: 14px; background: none; border: none;"
            )
            row.addWidget(icon_label)

            name_col = QVBoxLayout()
            name_col.setSpacing(1)

            display_name = QLabel(_TEST_DISPLAY_NAMES.get(name, name))
            display_name.setStyleSheet(RANDOMNESS_TEST_LABEL)
            name_col.addWidget(display_name)

            desc = QLabel(_TEST_DESCRIPTIONS.get(name, ""))
            desc.setStyleSheet(
                "color: #b0b0c0; font-size: 10px; background: none; border: none;"
            )
            name_col.addWidget(desc)

            row.addLayout(name_col, 1)

            status_label = QLabel("")
            status_label.setFixedWidth(50)
            status_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            status_label.setStyleSheet(RANDOMNESS_TEST_LABEL)
            row.addWidget(status_label)

            tests_layout.addLayout(row)
            self._test_rows[name] = (icon_label, display_name, status_label)

        layout.addWidget(tests_frame)
        layout.addSpacing(12)

        # Overall result
        self.overall_label = QLabel("")
        self.overall_label.setAlignment(Qt.AlignCenter)
        self.overall_label.setStyleSheet(
            "color: #9898a8; font-size: 14px; font-weight: 700;"
            " background: none; border: none;"
        )
        layout.addWidget(self.overall_label)

        layout.addStretch()

        # Close button (hidden until done)
        self.close_btn = QPushButton("Continue")
        self.close_btn.setFixedHeight(32)
        self.close_btn.setCursor(Qt.PointingHandCursor)
        self.close_btn.setStyleSheet(GENERATE_BTN)
        self.close_btn.clicked.connect(self.close)
        self.close_btn.hide()
        layout.addWidget(self.close_btn)

        # Connect signal and start
        self._result_ready.connect(self._on_result)
        QTimer.singleShot(100, self._start_test)

    def _start_test(self):
        def _run():
            result = verify_randomness(num_samples=3, sample_size=1024)
            self._result_ready.emit(result)
        threading.Thread(target=_run, daemon=True).start()

    def _on_result(self, result):
        # Stop indeterminate progress
        self.progress.setRange(0, 100)
        self.progress.setValue(100)

        all_pass = result["pass"]

        if all_pass:
            self.progress.setStyleSheet(
                "QProgressBar { background: #e8e8f0; border: none; border-radius: 3px; }"
                "QProgressBar::chunk { background: #2a9a5a; border-radius: 3px; }"
            )
            self.status_label.setText("All tests completed")
            self.status_label.setStyleSheet(
                "color: #2a9a5a; font-size: 11px; font-weight: 600;"
                " background: none; border: none;"
            )
        else:
            self.progress.setStyleSheet(
                "QProgressBar { background: #e8e8f0; border: none; border-radius: 3px; }"
                "QProgressBar::chunk { background: #d04040; border-radius: 3px; }"
            )
            self.status_label.setText("Issues detected")
            self.status_label.setStyleSheet(
                "color: #d04040; font-size: 11px; font-weight: 600;"
                " background: none; border: none;"
            )

        # Update each test row
        for test in result["tests"]:
            name = test["test"]
            passed = test["pass"]
            if name not in self._test_rows:
                continue
            icon_label, name_label, status_label = self._test_rows[name]

            if passed:
                icon_label.setText("\u2714")
                icon_label.setStyleSheet(
                    "font-size: 16px; color: #2a9a5a; background: none; border: none;"
                )
                name_label.setStyleSheet(RANDOMNESS_TEST_PASS)
                status_label.setText("PASS")
                status_label.setStyleSheet(RANDOMNESS_TEST_PASS)
            else:
                icon_label.setText("\u2718")
                icon_label.setStyleSheet(
                    "font-size: 16px; color: #d04040; background: none; border: none;"
                )
                name_label.setStyleSheet(RANDOMNESS_TEST_FAIL)
                status_label.setText("FAIL")
                status_label.setStyleSheet(RANDOMNESS_TEST_FAIL)

        # Overall
        if all_pass:
            self.overall_label.setText("\u2714  Entropy source is healthy")
            self.overall_label.setStyleSheet(
                "color: #2a9a5a; font-size: 14px; font-weight: 700;"
                " background: none; border: none;"
            )
        else:
            self.overall_label.setText("\u2718  Weak randomness detected!")
            self.overall_label.setStyleSheet(
                "color: #d04040; font-size: 14px; font-weight: 700;"
                " background: none; border: none;"
            )

        self.close_btn.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SeedTestWindow()
    window.show()
    sys.exit(app.exec())

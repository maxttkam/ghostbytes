"""Ghostbytes desktop application interface."""

import base64
import ctypes
import os
import sys
import textwrap
import threading
import webbrowser
from tkinter import PhotoImage, filedialog

import customtkinter as ctk
from CTkMessagebox import CTkMessagebox
from ctkfontawesome import icon_to_ctkimage
from PIL import Image
from ghostbytes import __version__, __license__, __link__
from ghostbytes.crypto.config import (
    AVAIL_ALG,
    AVAIL_HASH,
    AVAIL_HASH_STR,
    AVAIL_RANDOM_STR,
    AVAIL_SIGN_ALG,
    ENCRYPTED_SUFFIX,
    RSA_KEY_OUT_FORMAT,
    OVERWRITE_OPTIONS,
    COMMON_RSA_SIZE,
    RSA_SIZE_WARNING_THRESHOLD,
    CryptoConfig,
)
from ghostbytes.error import GeneralError, invalid_argument
from ghostbytes.gui import wrappers as wr
from ghostbytes.gui.theme import (
    ABOUT_BOX_CONTENT,
    ACCENT,
    ACCENT_BORDER,
    ACCENT_HOVER,
    ACCENT_ON,
    ACCENT_TINT,
    ACTIONS,
    CARD_HEIGHT,
    CARD_WIDTH,
    CAPABILITIES,
    DANGER,
    ICON_ICO,
    ICON_PNG,
    MONO_FONT,
    SIDEBAR_LABELS,
    SUCCESS,
    TABS,
    THEME,
    WARNING,
)

def _set_windows_app_id():
    if os.name == "nt":
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "Ghostbytes.Ghostbytes")


class App(ctk.CTk):
    """Main Ghostbytes application window."""

    def __init__(self):
        _set_windows_app_id()
        super().__init__()

        self.title("Ghostbytes - An file encryption utility")
        self._set_appearance_mode("system")
        try:
            if os.name == "nt":
                self.iconbitmap(default=str(ICON_ICO))
            else:
                self._taskbar_icon = PhotoImage(file=str(ICON_PNG))
                self.iconphoto(True, self._taskbar_icon)
        except Exception:
            pass
        self.geometry("1200x750")
        self.propagate(False)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Session-scoped "don't warn me again" flag for the large-RSA-key
        # warning (generation & use of keys above RSA_SIZE_WARNING_THRESHOLD).
        self._suppress_rsa_warning = False

        self.sidebar_buttons = []
        self._nav_icons = {}
        self.content = ctk.CTkScrollableFrame(
            self,
            corner_radius=0,
            fg_color=THEME["content_bg"]
        )
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)

        self.tab = TABS["HEADER"][0]
        self._build_sidebar()
        self._build_context()

    # ------------------------------------------------------------------ #
    # Sidebar / navigation
    # ------------------------------------------------------------------ #

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=210, fg_color=THEME["sidebar_bg"])
        sidebar.propagate(False)
        sidebar.grid(row=0, column=0, sticky="nsw")

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=18, pady=(22, 16))
        ctk.CTkLabel(
            brand,
            text="Ghostbytes",
            text_color=THEME["content_text"],
            font=self._font(
                16,
                "bold")).pack(
            side="left",
            padx=(
                8,
                 0))

        row_counter = 1
        for group, tabs in TABS.items():
            if group not in ("HEADER", "FOOTER"):
                label = ctk.CTkLabel(
                    sidebar, text_color=THEME["gray_text"], font=self._font(
                        11, weight="bold"), text=SIDEBAR_LABELS.get(
                        group, group.title()), anchor="w")
                label.grid(
                    row=row_counter,
                    column=0,
                    sticky="ew",
                    padx=18,
                    pady=(
                        14,
                        3))
                row_counter += 1
            for tab in tabs:
                active_icon = icon_to_ctkimage(
                    tab[0], fill=ACCENT, scale_to_width=15)
                inactive_icon = icon_to_ctkimage(
                    tab[0], fill=THEME["text_fg"], scale_to_width=15)
                is_active = tab == self.tab
                tab_button = ctk.CTkButton(
                    sidebar,
                    anchor="w",
                    corner_radius=8,
                    text_color=ACCENT if is_active else THEME["text_fg"],
                    fg_color=ACCENT_TINT if is_active else "transparent",
                    hover_color=THEME["box_color"],
                    font=self._font(size=13),
                    text=tab[1],
                    image=active_icon if is_active else inactive_icon,
                    command=lambda tab=tab: self._change_tabs(tab)
                )
                tab_button.grid(
                    row=row_counter,
                    column=0,
                    sticky="ew",
                    padx=12,
                    pady=2 if group != "FOOTER" else (30, 8)
                )
                self._nav_icons[tab_button] = (active_icon, inactive_icon)
                self.sidebar_buttons.append(tab_button)
                row_counter += 1
        sidebar.grid_rowconfigure(row_counter, weight=2)

    def _change_tabs(self, new_tab):
        self.tab = new_tab
        for btn in self.sidebar_buttons:
            active_icon, inactive_icon = self._nav_icons[btn]
            if btn._text == new_tab[1]:
                btn.configure(
                    fg_color=ACCENT_TINT,
                    text_color=ACCENT,
                    image=active_icon)
            else:
                btn.configure(
                    fg_color="transparent",
                    text_color=THEME["text_fg"],
                    image=inactive_icon)

        self._build_context()

    def _find_tab(self, label):
        for tabs in TABS.values():
            for tab in tabs:
                if tab[1] == label:
                    return tab
        return None

    def _build_context(self):
        switch = {
            "Home": self._build_home,
            "Encrypt / Decrypt": self._build_crypto,
            "Generate Key Pair": self._build_genkey,
            "Verify Key Pair": self._build_verifykey,
            "Key Information": self._build_keyinfo,
            "Sign / Verify": self._build_sign,
            "Hash File(s) (Checksum)": self._build_hashfile,
            "Random": self._build_random,
            "Password Generator": self._build_pwdgen,
            "Benchmark": self._build_benchmark,
            "Secure Delete": self._build_sdelete,
            "Wipe Free Space": self._build_wipe_space,
            "About": self._build_about
        }
        if self.tab[1] not in switch:
            self._error_win(
                "GUI Internal Error",
                f"Cannot find build function for tab `{
                    self.tab[1]}`",
                True)

        for widget in self.content.winfo_children():
            widget.destroy()
        switch[self.tab[1]]()

    # ------------------------------------------------------------------ #
    # Home
    # ------------------------------------------------------------------ #

    def _build_home(self):
        app_details = ctk.CTkFrame(
            self.content,
            corner_radius=0,
            fg_color="transparent")
        app_details.grid(row=0, column=0, sticky="new", padx=32, pady=(28, 18))
        app_details.grid_columnconfigure(1, weight=1)
        app_details.grid_columnconfigure(2, weight=0, minsize=250)

        try:
            icon = ctk.CTkImage(
                Image.open(ICON_PNG),
                Image.open(ICON_PNG),
                (64, 64)
            )
            ctk.CTkLabel(
                app_details,
                image=icon,
                text="",
                width=64).grid(
                row=0,
                column=0,
                sticky="nw")
        except Exception:
            pass

        text_frame = ctk.CTkFrame(app_details, fg_color="transparent")
        text_frame.grid(row=0, column=1, sticky="new", padx=(15, 0))

        ctk.CTkLabel(
            text_frame, text="Ghostbytes", text_color=THEME["content_text"],
            font=self._font(24, "bold"), anchor="w"
        ).pack(anchor="w")
        ctk.CTkLabel(
            text_frame, text="File Encryption Utility", text_color=ACCENT,
            font=self._font(13, "bold"), anchor="w"
        ).pack(anchor="w")
        ctk.CTkLabel(
            text_frame,
            text="Military-grade cryptographic toolkit for file encryption, key "
            "management, and secure data handling. Built for privacy.",
            text_color=THEME["slight_gray"],
            font=self._font(12),
            anchor="w",
            justify="left",
            wraplength=500).pack(
            anchor="w",
            pady=(
                4,
                0))

        about = ctk.CTkFrame(
            app_details,
            fg_color=THEME["box_color"],
            border_width=1,
            border_color=THEME["box_border"],
            corner_radius=THEME["corner_rad"])
        about.grid(row=0, column=2, sticky="ne", padx=(24, 0))
        about.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            about,
            text="About Ghostbytes",
            text_color=THEME["content_text"],
            font=self._font(
                13,
                "bold"),
            anchor="w").grid(
            row=0,
            column=0,
            columnspan=2,
            sticky="w",
            padx=14,
            pady=(
                10,
                4))
        for index, (label, value) in enumerate(
                (("Version", __version__), ("License", __license__), ("Source", __link__))):
            ctk.CTkLabel(
                about,
                text=label,
                text_color=THEME["slight_gray"],
                font=self._font(10),
                anchor="w").grid(
                row=index + 1,
                column=0,
                sticky="w",
                padx=14,
                pady=2)
            value_label = ctk.CTkLabel(
                about,
                text=value,
                text_color=ACCENT if label == "Source" else THEME["content_text"],
                font=self._mono_font(10),
                anchor="w",
                justify="left",
                wraplength=185,
                cursor="hand2" if label == "Source" else None)
            value_label.grid(
                row=index + 1,
                column=1,
                sticky="w",
                padx=(
                    8,
                    14),
                pady=2)
            if label == "Source":
                value_label.bind(
                    "<Button-1>",
                    lambda _event,
                    url=value: webbrowser.open_new_tab(url))
        ctk.CTkLabel(
            about,
            text="Privacy is not a feature. It's a foundation",
            text_color=THEME["slight_gray"],
            font=self._font(
                12,
                "bold"),
            anchor="w").grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="w",
            padx=14,
            pady=(
                8,
                10))

        divider = ctk.CTkFrame(
            self.content,
            height=1,
            fg_color=THEME["box_border"])
        divider.grid(row=1, column=0, sticky="ew", padx=32)

        quick_actions = ctk.CTkFrame(self.content, fg_color="transparent")
        quick_actions.grid(
            row=2,
            column=0,
            sticky="new",
            padx=32,
            pady=(
                20,
                20))

        ctk.CTkLabel(
            quick_actions,
            text="Quick Actions",
            text_color=THEME["content_text"],
            font=self._font(
                15,
                "bold"),
            anchor="w").grid(
            row=0,
            column=0,
            sticky="w",
            pady=(
                0,
                5))

        cards = [
            self._build_action_card(quick_actions, icon_name, title, desc, target)
            for icon_name, title, desc, target in ACTIONS
        ]

        quick_actions.bind(
            "<Configure>",
            lambda e: self._home_organise(
                quick_actions,
                cards))
        self.after(50, lambda: self._home_organise(quick_actions, cards))

    def _build_action_card(self, parent, icon_name, title, desc, target):
        card = ctk.CTkFrame(
            parent,
            width=CARD_WIDTH,
            height=CARD_HEIGHT,
            corner_radius=THEME["corner_rad"],
            fg_color=THEME["box_color"],
            border_color=THEME["box_border"],
            border_width=THEME["box_border_width"],
            cursor="hand2")
        card.grid_propagate(False)
        card.grid_columnconfigure(1, weight=1)

        badge = ctk.CTkFrame(
            card,
            width=32,
            height=32,
            corner_radius=8,
            fg_color=ACCENT_TINT)
        badge.grid(row=0, column=0, rowspan=2, sticky="nw", padx=12, pady=12)
        badge.grid_propagate(False)
        ctk.CTkLabel(
            badge,
            text="",
            image=icon_to_ctkimage(
                icon_name,
                fill=ACCENT,
                scale_to_width=14)).place(
            relx=0.5,
            rely=0.5,
            anchor="center")

        ctk.CTkLabel(
            card, text=title, text_color=THEME["content_text"],
            font=self._font(13, "bold"), anchor="w"
        ).grid(row=0, column=1, sticky="sw", padx=(0, 10), pady=(14, 0))

        ctk.CTkLabel(
            card,
            text=desc,
            text_color=THEME["slight_gray"],
            font=self._font(11),
            anchor="nw",
            justify="left",
            wraplength=CARD_WIDTH -
            60).grid(
            row=1,
            column=1,
            sticky="nw",
            padx=(
                0,
                10),
            pady=(
                2,
                10))

        def go(_event=None):
            tab = self._find_tab(target)
            if tab:
                self._change_tabs(tab)

        self._bind_recursive(card, go)
        card.bind("<Enter>", lambda e: card.configure(border_color=ACCENT))
        card.bind(
            "<Leave>", lambda e: card.configure(
                border_color=THEME["box_border"]))

        return card

    def _bind_recursive(self, widget, command):
        widget.bind("<Button-1>", command)
        for child in widget.winfo_children():
            self._bind_recursive(child, command)

    def _home_organise(self, quick_actions, cards):
        """Re-grid action cards into as many columns as fit the current frame width."""
        if not quick_actions.winfo_exists():
            return  # the user navigated away before this deferred call fired

        frame_width = quick_actions.winfo_width()
        if frame_width < 10:
            return

        cols = max(1, frame_width // (CARD_WIDTH + 10))

        for idx, card in enumerate(cards):
            row, col = divmod(idx, cols)
            card.grid(row=row + 1, column=col, sticky="nw", padx=5, pady=5)

        num_rows = -(-len(cards) // cols)
        heading_h = 30
        new_height = heading_h + num_rows * (CARD_HEIGHT + 10) + 10
        quick_actions.configure(height=new_height)

    # ------------------------------------------------------------------ #
    # Encrypt / Decrypt
    # ------------------------------------------------------------------ #

    def _build_crypto(self):
        self._page_header(
            "lock",
            "Encrypt / Decrypt",
            "Secure or restore one or more files.")
        page = self._page(row=1)

        row = 0
        self._section(page, row, "Mode")
        row += 1
        mode_var = ctk.StringVar(value="Encrypt")
        ctk.CTkSegmentedButton(
            page,
            values=[
                "Encrypt",
                "Decrypt"],
            variable=mode_var,
            fg_color=THEME["box_color"],
            selected_color=ACCENT,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=THEME["box_color"],
            text_color=THEME["content_text"],
            height=38,
            font=self._font(
                13,
                "bold"),
            command=lambda v: refresh()).grid(
                row=row,
                column=0,
                columnspan=2,
            sticky="ew")
        row += 1

        self._section(page, row, "Files")
        row += 1
        self._field_label(page, row, "Input files (comma and space separated)")
        row += 1
        in_entry = self._entry(page, row, "Choose one or more files")
        selected_inputs = []
        self._file_row(
            page,
            row,
            in_entry,
            multiple=True,
            selected=selected_inputs,
            on_browse=lambda: auto_output())
        row += 1

        self._field_label(page, row, "Output file")
        row += 1

        def auto_output(*_):
            src = selected_inputs[0] if selected_inputs else in_entry.get().split(",")[
                0].strip()
            if not src:
                return
            out_entry.delete(0, "end")
            if mode_var.get() == "Encrypt":
                out_entry.insert(0, src + ENCRYPTED_SUFFIX)
            else:
                out_entry.insert(0, wr.remove_encrypted_suffix(src))

        out_entry = self._entry(page, row, "Where to save the result")
        self._file_row(page, row, out_entry, save=True)
        row += 1

        in_entry.bind("<KeyRelease>", auto_output)

        self._section(page, row, "Protection")
        row += 1
        key_type_var = ctk.StringVar(value="AES (password)")
        ctk.CTkSegmentedButton(
            page,
            values=[
                "AES (password)",
                "ML-KEM (Post Quantum, pub-key auth)",
                "RSA (pub-key auth)"],
            variable=key_type_var,
            fg_color=THEME["box_color"],
            selected_color=ACCENT,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=THEME["box_color"],
            text_color=THEME["content_text"],
            height=38,
            font=self._font(
                13,
                "bold"),
            command=lambda _value: sync_protection_algorithm()).grid(
                row=row,
                column=0,
                columnspan=2,
                sticky="ew",
                pady=(
                    0,
                    6))
        row += 1
        key_row = row
        row += 1
        constructing_config = CryptoConfig()

        pwd_frame = ctk.CTkFrame(page, fg_color="transparent")
        pwd_frame.grid_columnconfigure(0, weight=1)
        pwd_entry = ctk.CTkEntry(
            pwd_frame, placeholder_text="Password", show="•",
            fg_color=THEME["box_color"], border_color=THEME["box_border"],
            text_color=THEME["content_text"]
        )
        pwd_entry.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        confirm_entry = ctk.CTkEntry(
            pwd_frame, placeholder_text="Confirm password", show="•",
            fg_color=THEME["box_color"], border_color=THEME["box_border"],
            text_color=THEME["content_text"]
        )
        confirm_entry.grid(row=1, column=0, sticky="ew", pady=(0, 6))

        rsa_frame = ctk.CTkFrame(page, fg_color="transparent")
        rsa_frame.grid_columnconfigure(0, weight=1)
        key_entry = ctk.CTkEntry(
            rsa_frame, placeholder_text="RSA key file (.pem)",
            fg_color=THEME["box_color"], border_color=THEME["box_border"],
            text_color=THEME["content_text"]
        )
        key_entry.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self._file_row(rsa_frame, 0, key_entry)
        pass_entry = ctk.CTkEntry(
            rsa_frame, placeholder_text="Key passphrase (if any)", show="•",
            fg_color=THEME["box_color"], border_color=THEME["box_border"],
            text_color=THEME["content_text"]
        )
        pass_entry.grid(
            row=1,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(
                0,
                6))
        rsa_mode_var, _menu = self._option_grid(
            rsa_frame, 2, [
                "Hybrid (any file size)", "Direct RSA-OAEP (small files only)"], label=None)

        def selected_algorithm():
            if key_type_var.get().startswith("AES"):
                return "aes"
            if key_type_var.get().startswith("RSA"):
                return "extended_oaep" if rsa_mode_var.get().startswith("Hybrid") else "rsa-oaep"
            if constructing_config.algorithm not in (
                    "ML-KEM-768", "ML-KEM-1024"):
                constructing_config.algorithm = "ML-KEM-768"
            return constructing_config.algorithm

        def sync_protection_algorithm(*_):
            constructing_config.algorithm = selected_algorithm()
            refresh()

        rsa_mode_var.trace_add("write", sync_protection_algorithm)

        mlkem_frame = ctk.CTkFrame(
            page,
            fg_color=ACCENT_TINT,
            border_width=1,
            border_color=ACCENT_BORDER)
        mlkem_frame.grid_columnconfigure(0, weight=1)
        mlkem_key_entry = ctk.CTkEntry(
            mlkem_frame,
            placeholder_text="ML-KEM key file (.pem or .der)",
            fg_color=THEME["box_color"],
            border_color=THEME["box_border"],
            text_color=THEME["content_text"])
        mlkem_key_entry.grid(
            row=0,
            column=0,
            columnspan=1,
            sticky="ew",
            padx=12,
            pady=(
                2,
                6))
        self._file_row(mlkem_frame, 0, mlkem_key_entry)
        mlkem_pass_entry = ctk.CTkEntry(
            mlkem_frame,
            placeholder_text="Key passphrase (if any)",
            show="•",
            fg_color=THEME["box_color"],
            border_color=THEME["box_border"],
            text_color=THEME["content_text"])
        mlkem_pass_entry.grid(
            row=1,
            column=0,
            columnspan=2,
            sticky="ew",
            padx=12,
            pady=(
                0,
                6))
        ctk.CTkLabel(
            mlkem_frame,
            text="ML-KEM is post-quantum lattice-based cryptography standardized by FIPS 203. "
            "The selected parameter set uses hybrid AES encryption.",
            text_color=THEME["content_text"],
            font=self._font(11),
            justify="left",
            anchor="w",
            wraplength=540).grid(
            row=2,
            column=0,
            columnspan=2,
            sticky="ew",
            padx=12,
            pady=10)

        adv_fields = {}
        self._advanced(
            page, row, lambda inner: adv_fields.update(
                self._build_config_fields(inner)))
        row += 1

        config_actions = ctk.CTkFrame(page, fg_color="transparent")
        config_actions.grid(
            row=row,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(
                2,
                8))

        def apply_config(config):
            constructing_config.__dict__.update(config.__dict__)
            if config.algorithm == "aes":
                key_type_var.set("AES (password)")
            elif config.algorithm == "extended_oaep":
                key_type_var.set("RSA (pub-key auth)")
                rsa_mode_var.set("Hybrid (any file size)")
            elif config.algorithm == "rsa-oaep":
                key_type_var.set("RSA (pub-key auth)")
                rsa_mode_var.set("Direct RSA-OAEP (small files only)")
            elif config.algorithm.startswith("ML-KEM-"):
                key_type_var.set("ML-KEM (Post Quantum, pub-key auth)")
            adv_fields["store_iv"].set(config.store_iv)
            adv_fields["mac_len"].delete(0, "end")
            adv_fields["mac_len"].insert(0, str(config.mac_len))
            adv_fields["kdf_salt"].delete(0, "end")
            adv_fields["kdf_salt"].insert(
                0, f"base64:{
                    base64.b64encode(
                        config.kdf_salt).decode('ascii')}")
            adv_fields["kdf_time"].delete(0, "end")
            adv_fields["kdf_time"].insert(0, str(config.kdf_time_cost))
            adv_fields["kdf_mem"].delete(0, "end")
            adv_fields["kdf_mem"].insert(
                0, str(config.kdf_memory_cost // 1024))
            adv_fields["kdf_par"].delete(0, "end")
            adv_fields["kdf_par"].insert(0, str(config.kdf_parallelism))
            adv_fields["hash"].set(
                AVAIL_HASH_STR[AVAIL_HASH.index(config.hash_func)])
            adv_fields["rand_func"].set(config.rand_func)
            refresh()

        def generate_config():
            try:
                config = self._config_from_fields(
                    adv_fields, allow_empty_salt=True, algorithm=selected_algorithm())
                config.generate_random_salt()
                constructing_config.kdf_salt = config.kdf_salt
                adv_fields["kdf_salt"].delete(0, "end")
                adv_fields["kdf_salt"].insert(
                    0, f"base64:{
                        base64.b64encode(
                            constructing_config.kdf_salt).decode('ascii')}")
            except GeneralError as error:
                self._error_win("Config generation failed", str(error))

        def export_config():
            try:
                config = self._config_from_fields(
                    adv_fields, algorithm=selected_algorithm())
                constructing_config.__dict__.update(config.__dict__)
                path = filedialog.asksaveasfilename(
                    defaultextension=".conf", filetypes=(
                        ("ghostbytes config", "*.conf"), ("All files", "*.*")), )
                if path:
                    constructing_config.export_file(path)
                    status.configure(
                        text=f"Config saved to {path}",
                        text_color=SUCCESS)
            except (OSError, ValueError) as e:
                self._error_win("Config export failed", str(e))

        def import_config():
            path = filedialog.askopenfilename(filetypes=(
                ("ghostbytes config", "*.conf"), ("All files", "*.*")), )
            if not path:
                return
            try:
                apply_config(CryptoConfig.import_file(path))
                status.configure(
                    text=f"Config loaded from {path}",
                    text_color=SUCCESS)
            except (OSError, ValueError, UnicodeDecodeError) as e:
                self._error_win("Config import failed", str(e))

        generate_button = self._ghost_button(
            config_actions,
            "Generate Config (Random Salt)",
            generate_config,
            width=190)
        export_button = self._ghost_button(
            config_actions, "Export Config", export_config, width=120)
        import_button = self._ghost_button(
            config_actions, "Import Config", import_config, width=120)
        generate_button.grid(row=0, column=0, sticky="w")
        export_button.grid(row=0, column=1, sticky="w", padx=(8, 0))
        import_button.grid(row=0, column=2, sticky="w", padx=(8, 0))
        row += 1

        btn, bar, status = self._run_row(page, row, "Run", None)

        def refresh(*_):
            aes_selected = key_type_var.get().startswith("AES")
            mlkem_selected = key_type_var.get().startswith("ML-KEM")
            kdf_visible = aes_selected or mlkem_selected
            for widget in adv_fields.get("kdf_widgets", []):
                if kdf_visible:
                    widget.grid()
                else:
                    widget.grid_remove()
            for widget in adv_fields.get("hash_widgets", []):
                if key_type_var.get().startswith("RSA"):
                    widget.grid()
                else:
                    widget.grid_remove()
            for widget in adv_fields.get("rand_widgets", []):
                if not aes_selected:
                    widget.grid()
                else:
                    widget.grid_remove()
            if mode_var.get() == "Encrypt":
                generate_button.grid()
                export_button.grid()
                import_button.grid_remove()
            else:
                generate_button.grid_remove()
                export_button.grid_remove()
                import_button.grid()
            if aes_selected:
                rsa_frame.grid_forget()
                mlkem_frame.grid_forget()
                pwd_frame.grid(
                    row=key_row,
                    column=0,
                    columnspan=2,
                    sticky="ew")
                if mode_var.get() == "Encrypt":
                    confirm_entry.grid()
                else:
                    confirm_entry.grid_remove()
            elif key_type_var.get().startswith("RSA"):
                pwd_frame.grid_forget()
                mlkem_frame.grid_forget()
                rsa_frame.grid(
                    row=key_row,
                    column=0,
                    columnspan=2,
                    sticky="ew")
            else:
                pwd_frame.grid_forget()
                rsa_frame.grid_forget()
                mlkem_frame.grid(
                    row=key_row,
                    column=0,
                    columnspan=2,
                    sticky="ew")
            auto_output()

        refresh()

        def do_run():
            try:
                config = self._config_from_fields(
                    adv_fields, algorithm=selected_algorithm())
            except ValueError as e:
                self._error_win("Invalid advanced settings", str(e))
                return

            src_paths = selected_inputs or [
                line.strip() for line in in_entry.get().split(",") if line.strip()]
            src, dst = (src_paths[0] if src_paths else ""), out_entry.get()
            if not src or not dst:
                self._error_win(
                    "Missing information",
                    "Please choose input file(s) and an output file path.")
                return

            mode = mode_var.get()

            def launch(key, passphrase):
                if mode == "Encrypt":
                    def work():
                        return wr.encrypt_paths(
                            src_paths, dst, config, key, passphrase)
                else:
                    def work():
                        return wr.decrypt_paths(
                            src_paths, dst, config, key, passphrase)
                self._run_async(
                    work,
                    btn,
                    bar,
                    status,
                    on_success=lambda res: status.configure(
                        text=f"Saved to {res}",
                        text_color=SUCCESS),
                    start_msg="Encrypting…" if mode == "Encrypt" else "Decrypting…",
                )

            if key_type_var.get().startswith("AES"):
                pw = pwd_entry.get()
                if not pw:
                    self._error_win(
                        "Missing information",
                        "Please enter a password.")
                    return
                if mode == "Encrypt" and pw != confirm_entry.get():
                    self._error_win(
                        "Password mismatch",
                        "Password and confirmation do not match.")
                    return
                config.algorithm = "aes"
                launch(pw.encode("utf-8"), None)
            elif key_type_var.get().startswith("RSA"):
                key_path = key_entry.get()
                if not key_path:
                    self._error_win(
                        "Missing information",
                        "Please choose an RSA key file.")
                    return
                algorithm = (
                    "extended_oaep"
                    if rsa_mode_var.get().startswith("Hybrid")
                    else "rsa-oaep")
                try:
                    with open(key_path, "rb") as f:
                        key = f.read()
                except OSError as e:
                    self._error_win("File error", str(e))
                    return
                passphrase = pass_entry.get() or None
                config.algorithm = algorithm
                launch(key, passphrase)
            else:
                key_path = mlkem_key_entry.get()
                if not key_path:
                    self._error_win(
                        "Missing information",
                        "Please choose an ML-KEM key file.")
                    return
                try:
                    with open(key_path, "rb") as f:
                        key = f.read()
                except OSError as e:
                    self._error_win("File error", str(e))
                    return
                try:
                    algorithm = wr.detect_mlkem_algorithm(
                        key, mlkem_pass_entry.get() or None)
                except Exception as e:
                    self._error_win("Key error", str(e))
                    return
                config.algorithm = algorithm
                launch(key, mlkem_pass_entry.get() or None)

        btn.configure(command=do_run)

    # ------------------------------------------------------------------ #
    # RSA key generation / verification / info
    # ------------------------------------------------------------------ #

    def _build_genkey(self):
        self._page_header(
            "key",
            "Generate Key Pair",
            "Create an RSA, ML-KEM, or ML-DSA public/private key pair.")
        page = self._page(row=1)
        row = 0
        self._section(page, row, "Key type")
        row += 1
        key_type_var = ctk.StringVar(value="RSA")
        ctk.CTkSegmentedButton(
            page,
            values=[
                "ML-KEM",
                "ML-DSA",
                "RSA"],
            variable=key_type_var,
            fg_color=THEME["box_color"],
            selected_color=ACCENT,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=THEME["box_color"],
            text_color=THEME["content_text"],
            height=38,
            font=self._font(
                13,
                "bold"),
            command=lambda _value: refresh_type(),
        ).grid(
            row=row,
            column=0,
            columnspan=2,
            sticky="ew")
        row += 1

        rsa_frame = ctk.CTkFrame(page, fg_color="transparent")
        rsa_frame.grid_columnconfigure(0, weight=1)
        self._field_label(rsa_frame, 0, "RSA key size")
        rsa_size_var, _ = self._option(
            rsa_frame, 1, [str(s) for s in COMMON_RSA_SIZE] + ["Custom…"],
            default="2048", command=lambda _value: refresh_rsa_size()
        )
        custom_rsa_entry = self._entry(
            rsa_frame, 2, "Custom RSA key size in bits")
        custom_rsa_entry.grid_remove()
        self._field_label(rsa_frame, 3, "Public exponent")
        exponent_entry = self._entry(rsa_frame, 4, default="65537")
        self._field_label(rsa_frame, 5, "Output format")
        rsa_format_var, _ = self._option(rsa_frame, 6, RSA_KEY_OUT_FORMAT)

        mlkem_frame = ctk.CTkFrame(page, fg_color="transparent")
        mlkem_frame.grid_columnconfigure(0, weight=1)
        self._field_label(mlkem_frame, 0, "ML-KEM parameter set")
        mlkem_values = [
            algorithm for algorithm in AVAIL_ALG if algorithm.startswith("ML-KEM-")]
        mlkem_alg_var, _ = self._option(mlkem_frame, 1, mlkem_values)
        ctk.CTkLabel(
            mlkem_frame,
            text=(
                "ML-KEM-768 corresponds to Post-Quantum Security Level 3; "
                "ML-KEM-1024 corresponds to Level 5 (NIST) "
                "(Equivalent to AES-256)."),
            text_color=THEME["gray_text"],
            font=self._font(10),
            anchor="w",
            justify="left",
            wraplength=560).grid(
            row=2,
            column=0,
            sticky="w",
            pady=(
                4,
                0))
        self._field_label(mlkem_frame, 3, "Output format")
        mlkem_format_var, _ = self._option(mlkem_frame, 4, ["PEM", "DER"])

        mldsa_frame = ctk.CTkFrame(page, fg_color="transparent")
        mldsa_frame.grid_columnconfigure(0, weight=1)
        self._section(mldsa_frame, 0, "Signature key")
        self._field_label(mldsa_frame, 1, "ML-DSA parameter set")
        mldsa_values = [
            algorithm for algorithm in AVAIL_SIGN_ALG
            if algorithm.startswith("ML-DSA-")]
        mldsa_alg_var, _ = self._option(mldsa_frame, 2, mldsa_values)
        ctk.CTkLabel(
            mldsa_frame,
            text="ML-DSA is the FIPS 204 post-quantum digital signature standard.",
            text_color=THEME["gray_text"],
            font=self._font(10),
            anchor="w",
            justify="left",
            wraplength=560).grid(
            row=3,
            column=0,
            sticky="w",
            pady=(4, 0))
        self._field_label(mldsa_frame, 4, "Output format")
        mldsa_format_var, _ = self._option(mldsa_frame, 5, ["PEM", "DER"])

        rsa_frame.grid(row=row, column=0, columnspan=2, sticky="ew")
        row += 1
        self._field_label(
            page, row, "Passphrase (optional, protects private key)")
        row += 1
        pass_entry = self._entry(
            page, row, "Leave blank for no passphrase", show="•")
        row += 1
        self._section(page, row, "Save to")
        row += 1
        self._field_label(page, row, "Private key file")
        row += 1
        private_entry = self._entry(
            page, row, "Browse for the private key output file")
        self._file_row(page, row, private_entry, save=True,
                       on_browse=lambda: derive_public_path())
        row += 1
        self._field_label(page, row, "Public key file")
        row += 1
        public_entry = self._entry(page, row, "Public key output file")
        self._file_row(page, row, public_entry, save=True,
                       on_browse=lambda: derive_private_from_public())
        row += 1

        def derive_public_path(_event=None):
            private_path = private_entry.get()
            if private_path:
                stem, extension = os.path.splitext(private_path)
                public_entry.delete(0, "end")
                public_entry.insert(0, f"{stem}_pub{extension}")

        def derive_private_from_public(_event=None):
            public_path = public_entry.get()
            if public_path:
                stem, extension = os.path.splitext(public_path)
                private_entry.delete(0, "end")
                private_entry.insert(
                    0, f"{stem[:-4] if stem.endswith('_pub') else stem}{extension}")

        private_entry.bind("<KeyRelease>", derive_public_path)
        private_entry.bind("<FocusOut>", derive_public_path)
        btn, bar, status = self._run_row(page, row, "Generate", None)

        def refresh_type():
            if key_type_var.get() == "RSA":
                mlkem_frame.grid_forget()
                mldsa_frame.grid_forget()
                rsa_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
            elif key_type_var.get() == "ML-KEM":
                mldsa_frame.grid_forget()
                rsa_frame.grid_forget()
                mlkem_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
            else:
                mlkem_frame.grid_forget()
                rsa_frame.grid_forget()
                mldsa_frame.grid(row=2, column=0, columnspan=2, sticky="ew")

        def refresh_rsa_size():
            if rsa_size_var.get() == "Custom…":
                custom_rsa_entry.grid()
            else:
                custom_rsa_entry.grid_remove()

        def do_run():
            priv_path = private_entry.get().strip()
            pub_path = public_entry.get().strip()
            if not priv_path or not pub_path:
                self._error_win(
                    "Missing information",
                    "Please choose private and public key output files.")
                return

            key_size = None
            if key_type_var.get() == "RSA":
                try:
                    key_size = int(
                        custom_rsa_entry.get()) if rsa_size_var.get() == "Custom…" else int(
                        rsa_size_var.get())
                except ValueError:
                    self._error_win(
                        "Invalid input",
                        "RSA key size must be numeric.")
                    return

            def work():
                if key_type_var.get() == "RSA":
                    pub, priv = wr.generate_rsa_keypair(key_size, int(
                        exponent_entry.get()), pass_entry.get() or None, rsa_format_var.get())
                elif key_type_var.get() == "ML-KEM":
                    pub, priv = wr.generate_mlkem_keypair(
                        mlkem_alg_var.get(), mlkem_format_var.get(), pass_entry.get() or None)
                else:
                    pub, priv = wr.generate_mldsa_keypair(
                        mldsa_alg_var.get(), mldsa_format_var.get(), pass_entry.get() or None)
                os.makedirs(os.path.dirname(priv_path) or ".", exist_ok=True)
                with open(pub_path, "wb") as file:
                    file.write(pub)
                with open(priv_path, "wb") as file:
                    file.write(priv)
                return pub_path, priv_path

            def launch():
                self._run_async(
                    work,
                    btn,
                    bar,
                    status,
                    on_success=lambda result: status.configure(
                        text=f"Saved {
                            os.path.basename(
                                result[0])} and {
                            os.path.basename(
                                result[1])}",
                        text_color=SUCCESS),
                    start_msg="Generating key pair…",
                )

            if key_size is None:
                launch()
            else:
                self._confirm_large_rsa(key_size, launch)

        btn.configure(command=do_run)
        refresh_type()

    def _build_verifykey(self):
        self._page_header(
            "circle-check",
            "Verify Key Pair",
            "Check whether a public and private key match; key types are detected automatically.")
        page = self._page(row=1)

        row = 0
        self._field_label(page, row, "Public key file")
        row += 1
        pub_entry = self._entry(page, row, "Public key (.pem)")
        self._file_row(
            page,
            row,
            pub_entry,
            on_browse=lambda: derive_private_path())
        row += 1

        self._field_label(page, row, "Private key file")
        row += 1
        priv_entry = self._entry(page, row, "Private key (.pem)")
        self._file_row(
            page,
            row,
            priv_entry,
            on_browse=lambda: derive_public_path())
        row += 1

        def derive_private_path(_event=None):
            public_path = pub_entry.get()
            if public_path:
                stem, extension = os.path.splitext(public_path)
                private_entry_value = f"{stem[:-
                                              4] if stem.endswith('_pub') else stem}{extension}"
                priv_entry.delete(0, "end")
                priv_entry.insert(0, private_entry_value)

        def derive_public_path(_event=None):
            private_path = priv_entry.get()
            if private_path:
                stem, extension = os.path.splitext(private_path)
                pub_entry.delete(0, "end")
                pub_entry.insert(0, f"{stem}_pub{extension}")

        pub_entry.bind("<KeyRelease>", derive_private_path)
        pub_entry.bind("<FocusOut>", derive_private_path)
        priv_entry.bind("<KeyRelease>", derive_public_path)
        priv_entry.bind("<FocusOut>", derive_public_path)

        self._field_label(page, row, "Passphrase (if any)")
        row += 1
        pass_entry = self._entry(page, row, show="•")
        row += 1

        btn, bar, status = self._run_row(page, row, "Verify", None)

        def do_run():
            pub_path, priv_path = pub_entry.get(), priv_entry.get()
            if not pub_path or not priv_path:
                self._error_win(
                    "Missing information",
                    "Please choose both key files.")
                return

            def work():
                with open(pub_path, "rb") as f:
                    pub = f.read()
                with open(priv_path, "rb") as f:
                    priv = f.read()
                return wr.verify_keypair(pub, priv, pass_entry.get() or None)

            def on_success(matches):
                if matches:
                    status.configure(
                        text="✓ The key pair matches.",
                        text_color=SUCCESS)
                else:
                    status.configure(
                        text="✗ The key pair does NOT match.",
                        text_color=DANGER)

            self._run_async(
                work,
                btn,
                bar,
                status,
                on_success=on_success,
                start_msg="Verifying…")

        btn.configure(command=do_run)

    def _build_keyinfo(self):
        self._page_header(
            "key",
            "Key Information",
            "Inspect a key and check whether it is cryptographically usable.")
        page = self._page(row=1)

        row = 0
        self._field_label(page, row, "Key file")
        row += 1
        key_entry = self._entry(page, row, "Public or private key (.pem/.der)")
        self._file_row(page, row, key_entry)
        row += 1

        self._field_label(page, row, "Passphrase (if any)")
        row += 1
        pass_entry = self._entry(page, row, show="•")
        row += 1

        btn, bar, status = self._run_row(page, row, "Inspect", None)
        row += 2

        result_box = ctk.CTkFrame(
            page,
            fg_color=THEME["box_color"],
            border_width=1,
            border_color=THEME["box_border"],
            corner_radius=THEME["corner_rad"])
        result_box.grid(
            row=row,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(
                6,
                0))
        result_box.grid_columnconfigure(1, weight=1)
        result_box.grid_remove()

        def do_run():
            path = key_entry.get()
            if not path:
                self._error_win(
                    "Missing information",
                    "Please choose a key file.")
                return

            def work():
                with open(path, "rb") as f:
                    data = f.read()
                return wr.key_info(data, pass_entry.get() or None)

            def on_success(info):
                for child in result_box.winfo_children():
                    child.destroy()
                for i, (k, v) in enumerate(info.items()):
                    ctk.CTkLabel(
                        result_box,
                        text=k,
                        text_color=THEME["slight_gray"],
                        font=self._font(12)).grid(
                        row=i,
                        column=0,
                        sticky="w",
                        padx=14,
                        pady=8)
                    ctk.CTkLabel(
                        result_box,
                        text=v,
                        text_color=THEME["content_text"],
                        font=self._mono_font(12)).grid(
                        row=i,
                        column=1,
                        sticky="w",
                        padx=14,
                        pady=8)
                result_box.grid()

            self._run_async(
                work,
                btn,
                bar,
                status,
                on_success=on_success,
                start_msg="Reading key…")

        btn.configure(command=do_run)

    # ------------------------------------------------------------------ #
    # Hash files (single, multi-file, or whole folder), Random, Password
    # generator, Benchmark
    # ------------------------------------------------------------------ #

    def _build_sign(self):
        self._page_header(
            "file-signature",
            "Sign / Verify",
            "Create or verify a detached signature for a file.")
        page = self._page(row=1)
        row = 0
        mode_var = ctk.StringVar(value="Sign")
        self._section(page, row, "Mode")
        row += 1
        ctk.CTkSegmentedButton(
            page,
            values=[
                "Sign",
                "Verify"],
            variable=mode_var,
            fg_color=THEME["box_color"],
            selected_color=ACCENT,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=THEME["box_color"],
            text_color=THEME["content_text"],
            height=38,
            font=self._font(
                13,
                "bold"),
            command=lambda v: refresh()).grid(
                row=row,
                column=0,
                columnspan=2,
            sticky="ew")
        row += 1

        self._section(page, row, "Files")
        row += 1
        self._field_label(page, row, "File")
        row += 1
        file_entry = self._entry(page, row, "File to sign or verify")
        self._file_row(page, row, file_entry)
        row += 1

        self._section(page, row, "Protection")
        row += 1
        self._field_label(page, row, "Algorithm")
        row += 1
        algorithm_var, _ = self._option(
            page,
            row,
            ["RSA", "ML-DSA"],
            command=lambda _value: refresh())
        row += 1
        self._field_label(page, row, "Key file")
        row += 1
        key_entry = self._entry(page, row, "Private key for signing, public key for verification")
        self._file_row(page, row, key_entry)
        row += 1
        self._field_label(page, row, "Key passphrase (if any)")
        row += 1
        pass_entry = self._entry(page, row, show="•")
        row += 1

        self._section(page, row, "Output")
        row += 1
        self._field_label(page, row, "Signature file")
        row += 1
        signature_entry = self._entry(page, row, "Detached signature file")
        signature_browse = self._file_row(page, row, signature_entry, save=True)
        row += 1

        signing_advanced = ctk.CTkFrame(page, fg_color="transparent")
        signing_advanced.grid(
            row=row,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(8, 4))
        signing_advanced.grid_columnconfigure(0, weight=1)
        signing_advanced_inner = ctk.CTkFrame(
            signing_advanced,
            fg_color=ACCENT_TINT,
            border_width=1,
            border_color=ACCENT_BORDER,
            corner_radius=THEME["corner_rad"])
        signing_advanced_inner.grid_columnconfigure(0, weight=1)
        signing_advanced_inner.grid_columnconfigure(1, weight=1)
        signing_advanced_state = {"open": False}
        signing_hash_var, _ = self._option_grid(
            signing_advanced_inner,
            0,
            AVAIL_HASH_STR,
            label="Hash function")

        def toggle_signing_advanced():
            signing_advanced_state["open"] = not signing_advanced_state["open"]
            if signing_advanced_state["open"]:
                signing_advanced_inner.grid(
                    row=1, column=0, sticky="ew", pady=(8, 0))
                signing_advanced_button.configure(
                    text="▾  Advanced settings (RSA signature fields)")
            else:
                signing_advanced_inner.grid_forget()
                signing_advanced_button.configure(
                    text="▸  Advanced settings (RSA signature fields)")

        signing_advanced_button = ctk.CTkButton(
            signing_advanced,
            text="▸  Advanced settings (RSA signature fields)",
            anchor="w",
            fg_color="transparent",
            hover_color=THEME["box_color"],
            text_color=ACCENT,
            font=self._font(12, "bold"),
            command=toggle_signing_advanced)
        signing_advanced_button.grid(row=0, column=0, sticky="ew")
        signing_advanced_inner.grid_remove()
        row += 1

        btn, bar, status = self._run_row(page, row, "Sign", None)

        def refresh(*_):
            verifying = mode_var.get() == "Verify"
            rsa_selected = algorithm_var.get() == "RSA"
            btn.configure(text="Verify" if verifying else "Sign")
            pass_entry.configure(state="disabled" if verifying else "normal")
            signature_browse.configure(state="normal")
            if rsa_selected:
                signing_advanced.grid()
            else:
                signing_advanced.grid_remove()

        def do_run():
            file_path = file_entry.get().strip()
            key_path = key_entry.get().strip()
            signature_path = signature_entry.get().strip()
            if not file_path or not key_path or not signature_path:
                self._error_win(
                    "Missing information",
                    "Please choose the file, key, and signature file.")
                return

            def work():
                with open(file_path, "rb") as file:
                    message = file.read()
                with open(key_path, "rb") as file:
                    key = file.read()
                if mode_var.get() == "Sign":
                    signature = wr.sign_message(
                        algorithm_var.get(),
                        key,
                        message,
                        pass_entry.get() or None,
                        signing_hash_var.get())
                    with open(signature_path, "wb") as file:
                        file.write(signature)
                    return True
                with open(signature_path, "rb") as file:
                    signature = file.read()
                return wr.verify_signature(
                    algorithm_var.get(),
                    key,
                    message,
                    signature,
                    signing_hash_var.get())

            def on_success(result):
                if mode_var.get() == "Sign":
                    status.configure(text=f"Signature saved to {signature_path}", text_color=SUCCESS)
                else:
                    status.configure(
                        text="Signature is valid." if result else "Signature is invalid.",
                        text_color=SUCCESS if result else DANGER)

            self._run_async(
                work, btn, bar, status, on_success=on_success,
                start_msg="Signing…" if mode_var.get() == "Sign" else "Verifying…")

        btn.configure(command=do_run)
        refresh()

    def _build_hashfile(self):
        self._page_header(
            "hashtag",
            "Hash File(s) (Checksum)",
            "Compute a cryptographic digest for files or an entire folder.")
        page = self._page(row=1)

        row = 0
        self._section(page, row, "Source")
        row += 1
        mode_var = ctk.StringVar(value="Files")
        ctk.CTkSegmentedButton(
            page,
            values=[
                "Files",
                "Folder"],
            variable=mode_var,
            fg_color=THEME["box_color"],
            selected_color=ACCENT,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=THEME["box_color"],
            text_color=THEME["content_text"],
            command=lambda v: refresh()).grid(
            row=row,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(
                0,
                6))
        row += 1

        self._field_label(page, row, "Hash algorithm")
        row += 1
        alg_var, _ = self._option(page, row, AVAIL_HASH_STR)
        row += 1
        mode_row = row
        row += 1

        files_frame = ctk.CTkFrame(page, fg_color="transparent")
        files_frame.grid_columnconfigure(0, weight=1)
        files_box = ctk.CTkTextbox(
            files_frame,
            height=70,
            fg_color=THEME["box_color"],
            text_color=THEME["content_text"],
            font=self._mono_font(11))
        files_box.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 6))
        files_box.configure(state="disabled")
        selected = []

        def browse_files():
            paths = filedialog.askopenfilenames()
            if paths:
                selected.clear()
                selected.extend(paths)
                files_box.configure(state="normal")
                files_box.delete("1.0", "end")
                files_box.insert("1.0", "\n".join(selected))
                files_box.configure(state="disabled")
                refresh_checksum_path()

        self._ghost_button(
            files_frame,
            "Choose files…",
            browse_files).grid(
            row=1,
            column=1,
            sticky="e")

        folder_frame = ctk.CTkFrame(page, fg_color="transparent")
        folder_frame.grid_columnconfigure(0, weight=1)
        folder_entry = ctk.CTkEntry(
            folder_frame,
            placeholder_text="Folder to hash (recursive)",
            fg_color=THEME["box_color"],
            border_color=THEME["box_border"],
            text_color=THEME["content_text"])
        folder_entry.grid(row=0, column=0, sticky="ew")
        self._file_row(folder_frame, 0, folder_entry, dir_only=True)

        def refresh(*_):
            if mode_var.get() == "Files":
                folder_frame.grid_forget()
                files_frame.grid(
                    row=mode_row,
                    column=0,
                    columnspan=2,
                    sticky="ew")
            else:
                files_frame.grid_forget()
                folder_frame.grid(
                    row=mode_row,
                    column=0,
                    columnspan=2,
                    sticky="ew")

        refresh()

        self._section(page, row, "Output")
        row += 1
        save_var = self._checkbox(page, row, "Save results to a checksum file")
        row += 1
        out_entry = self._entry(page, row, "Where to save the checksum file")
        browse_btn = self._file_row(page, row, out_entry, save=True)
        out_entry.grid_remove()
        browse_btn.grid_remove()
        row += 1

        def toggle_save(*_):
            if save_var.get():
                out_entry.grid()
                browse_btn.grid()
                refresh_checksum_path()
            else:
                out_entry.grid_remove()
                browse_btn.grid_remove()

        def refresh_checksum_path(*_):
            if not save_var.get():
                return
            if mode_var.get() == "Files" and selected:
                base = wr.checksum_root(selected)
            elif mode_var.get() == "Folder" and folder_entry.get():
                base = wr.checksum_root([folder_entry.get()])
            else:
                base = "."
            out_entry.delete(0, "end")
            out_entry.insert(
                0, os.path.join(
                    base, wr.checksum_suffix(
                        alg_var.get())))

        save_var.trace_add("write", lambda *_: toggle_save())
        alg_var.trace_add("write", refresh_checksum_path)
        folder_entry.bind("<KeyRelease>", refresh_checksum_path)

        bar = ctk.CTkProgressBar(
            page, mode="determinate", progress_color=ACCENT)
        bar.set(0)
        bar.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        row += 1
        status = ctk.CTkLabel(
            page,
            text="",
            text_color=THEME["slight_gray"],
            font=self._font(11),
            anchor="w")
        status.grid(row=row, column=0, sticky="w", pady=(6, 0))
        btn = self._primary_button(page, "Compute Hashes")
        btn.grid(row=row, column=1, sticky="e", pady=(6, 0))
        row += 1

        results_box = ctk.CTkTextbox(
            page,
            height=180,
            fg_color=THEME["box_color"],
            text_color=THEME["content_text"],
            font=self._mono_font(11))
        results_box.grid(
            row=row,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(
                10,
                0))
        results_box.configure(state="disabled")

        def do_run():
            alg = alg_var.get()
            if mode_var.get() == "Files":
                if not selected:
                    self._error_win(
                        "Missing information",
                        "Please choose at least one file.")
                    return
                entries = [(os.path.basename(p), p) for p in selected]
            else:
                folder = folder_entry.get()
                if not folder:
                    self._error_win(
                        "Missing information",
                        "Please choose a folder.")
                    return
                try:
                    entries = wr.collect_folder_files(folder)
                except Exception as e:
                    self._error_win("Folder error", str(e))
                    return
                if not entries:
                    self._error_win(
                        "Empty folder",
                        "No files were found in that folder.")
                    return

            save_checksum = save_var.get()
            out_path = out_entry.get() if save_checksum else None
            if save_checksum and not out_path:
                self._error_win(
                    "Missing information",
                    "Please choose where to save the checksum file.")
                return

            btn.configure(state="disabled")
            bar.set(0)
            results_box.configure(state="normal")
            results_box.delete("1.0", "end")
            results_box.configure(state="disabled")
            status.configure(text="Starting…", text_color=THEME["slight_gray"])

            def progress_cb(done, total, label):
                self.after(
                    0,
                    lambda: (
                        bar.set(
                            done / total),
                        status.configure(
                            text=f"{done}/{total}: {label}")))

            def target():
                try:
                    hash_entries = (
                        wr.checksum_entries_for_output(entries, out_path)
                        if save_checksum else entries
                    )
                    results = wr.hash_paths(
                        hash_entries, alg, progress_cb=progress_cb)
                    if save_checksum:
                        wr.write_checksum_file(out_path, results)
                except Exception as e:
                    message = str(e)
                    self.after(
                        0, lambda: (
                            btn.configure(
                                state="normal"), status.configure(
                                text=f"Failed: {message}", text_color=DANGER), self._error_win(
                                "Operation Failed", message)))
                    return

                def finish():
                    btn.configure(state="normal")
                    bar.set(1.0)
                    results_box.configure(state="normal")
                    results_box.delete("1.0", "end")
                    for label, digest in results:
                        results_box.insert("end", f"{digest}  {label}\n")
                    results_box.configure(state="disabled")
                    msg = f"Done — {len(results)} file(s) hashed."
                    if save_checksum:
                        msg += f" Saved to {out_path}"
                    status.configure(text=msg, text_color=SUCCESS)

                self.after(0, finish)

            threading.Thread(target=target, daemon=True).start()

        btn.configure(command=do_run)

    def _build_random(self):
        self._page_header(
            "dice",
            "Random",
            "Generate cryptographically random data.")
        page = self._page(row=1)

        row = 0
        self._field_label(page, row, "Source")
        row += 1
        src_var, _ = self._option(page, row, AVAIL_RANDOM_STR)
        row += 1

        self._field_label(page, row, "Length (bytes)")
        row += 1
        len_entry = self._entry(page, row, default="32")
        row += 1

        self._field_label(page, row, "Output format")
        row += 1
        out_var, _ = self._option(page, row, ["Hex", "Base64", "Save to file"])
        row += 1

        out_entry = self._entry(page, row, "Where to save the random data")
        browse_btn = self._file_row(page, row, out_entry, save=True)
        out_entry.grid_remove()
        browse_btn.grid_remove()
        row += 1

        def toggle_output(*_):
            if out_var.get() == "Save to file":
                out_entry.grid()
                browse_btn.grid()
            else:
                out_entry.grid_remove()
                browse_btn.grid_remove()

        out_var.trace_add("write", lambda *_: toggle_output())

        btn, bar, status = self._run_row(page, row, "Generate", None)
        row += 2

        result_box = ctk.CTkTextbox(
            page,
            height=90,
            fg_color=THEME["box_color"],
            text_color=THEME["content_text"],
            font=self._mono_font(12))
        result_box.grid(
            row=row,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(
                0,
                0))
        result_box.configure(state="disabled")

        toggle_output()

        def do_run():
            try:
                length = int(len_entry.get())
            except ValueError:
                self._error_win(
                    "Invalid input",
                    "Length must be a whole number.")
                return

            def work():
                return wr.random_bytes(src_var.get(), length)

            def on_success(data):
                fmt = out_var.get()
                if fmt == "Save to file":
                    path = out_entry.get()
                    if not path:
                        status.configure(
                            text="No output file chosen — showing as hex instead.",
                            text_color=WARNING)
                        text = data.hex()
                    else:
                        with open(path, "wb") as f:
                            f.write(data)
                        status.configure(
                            text=f"Saved to {path}", text_color=SUCCESS)
                        return
                elif fmt == "Base64":
                    text = base64.b64encode(data).decode("ascii")
                else:
                    text = data.hex()
                result_box.configure(state="normal")
                result_box.delete("1.0", "end")
                result_box.insert("1.0", text)
                result_box.configure(state="disabled")

            self._run_async(
                work,
                btn,
                bar,
                status,
                on_success=on_success,
                start_msg="Generating…")

        btn.configure(command=do_run)

    def _build_pwdgen(self):
        self._page_header(
            "dice",
            "Password Generator",
            "Create a strong, random passphrase.")
        page = self._page(row=1)

        row = 0
        self._field_label(page, row, "Length (characters)")
        row += 1
        len_entry = self._entry(page, row, default="16")
        row += 1

        self._field_label(page, row, "Random source")
        row += 1
        src_var, _ = self._option(
            page, row, AVAIL_RANDOM_STR, command=lambda v: try_generate(False))
        row += 1

        upper_var = self._checkbox(page, row, "Uppercase letters (A–Z)", True)
        row += 1
        lower_var = self._checkbox(page, row, "Lowercase letters (a–z)", True)
        row += 1
        digit_var = self._checkbox(page, row, "Digits (0–9)", True)
        row += 1
        symbol_var = self._checkbox(page, row, "Symbols (!@#$…)", True)
        row += 1

        result_entry = ctk.CTkEntry(
            page,
            fg_color=THEME["box_color"],
            border_color=THEME["box_border"],
            text_color=THEME["content_text"],
            font=self._mono_font(14))
        result_entry.grid(row=row, column=0, sticky="ew", pady=(10, 0))

        def copy():
            self.clipboard_clear()
            self.clipboard_append(result_entry.get())
            status.configure(text="Copied to clipboard.", text_color=SUCCESS)

        self._ghost_button(
            page, "Copy", copy, width=70).grid(
            row=row, column=1, sticky="w", padx=(
                8, 0), pady=(
                10, 0))
        row += 1

        status = ctk.CTkLabel(
            page,
            text="",
            text_color=THEME["slight_gray"],
            font=self._font(11),
            anchor="w")
        status.grid(row=row, column=0, sticky="w", pady=(6, 0))

        def try_generate(show_errors):
            try:
                length = int(len_entry.get())
            except ValueError:
                if show_errors:
                    self._error_win(
                        "Invalid input",
                        "Length must be a whole number.")
                return
            try:
                pwd = wr.generate_password(
                    length,
                    upper_var.get(),
                    lower_var.get(),
                    digit_var.get(),
                    symbol_var.get(),
                    random_source=src_var.get())
            except GeneralError as e:
                if show_errors:
                    self._error_win("Cannot generate", str(e))
                return
            result_entry.delete(0, "end")
            result_entry.insert(0, pwd)
            status.configure(text="", text_color=THEME["slight_gray"])

        self._primary_button(
            page,
            "Regenerate",
            lambda: try_generate(True)).grid(
            row=row,
            column=1,
            sticky="e",
            pady=(
                6,
                0))

        for var in (upper_var, lower_var, digit_var, symbol_var):
            var.trace_add("write", lambda *_: try_generate(False))
        len_entry.bind("<KeyRelease>", lambda e: try_generate(False))

        try_generate(True)

    def _build_benchmark(self):
        self._page_header(
            "gauge-high",
            "Benchmark",
            "Measure this machine's cryptographic performance.")
        page = self._page(row=1)

        row = 0
        self._field_label(page, row, "Data size (bytes, default 1024)")
        row += 1
        len_entry = self._entry(page, row, default="1024")
        row += 1
        self._field_label(page, row, "RSA key size")
        row += 1
        rsa_var, _ = self._option(
            page, row, [
                str(size) for size in COMMON_RSA_SIZE], default="2048")
        row += 1
        ctk.CTkLabel(
            page,
            text="Direct RSA-OAEP cannot benchmark messages larger than the selected key permits; "
            "those rows will report an error instead of a timing.",
            text_color=THEME["gray_text"],
            font=self._font(10),
            anchor="w",
            justify="left",
            wraplength=560).grid(
            row=row,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(
                0,
                4))
        row += 1

        bar = ctk.CTkProgressBar(
            page, mode="determinate", progress_color=ACCENT)
        bar.set(0)
        bar.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        row += 1
        status = ctk.CTkLabel(
            page,
            text="",
            text_color=THEME["slight_gray"],
            font=self._font(11),
            anchor="w")
        status.grid(row=row, column=0, sticky="w", pady=(6, 8))
        btn = self._primary_button(page, "Run Benchmark")
        btn.grid(row=row, column=1, sticky="e", pady=(6, 8))
        row += 1

        results_box = ctk.CTkTextbox(
            page,
            height=260,
            fg_color=THEME["box_color"],
            text_color=THEME["content_text"],
            font=self._mono_font(12))
        results_box.grid(
            row=row,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(
                0,
                0))
        results_box.configure(state="disabled")

        def do_run():
            try:
                length = int(len_entry.get())
                keysize = int(rsa_var.get())
            except ValueError:
                self._error_win("Invalid input",
                                "Data size and key size must be numeric.")
                return

            def launch():
                algorithms = AVAIL_HASH_STR + AVAIL_ALG + AVAIL_SIGN_ALG + AVAIL_RANDOM_STR
                btn.configure(state="disabled")
                bar.set(0)
                results_box.configure(state="normal")
                results_box.delete("1.0", "end")
                results_box.configure(state="disabled")

                def target():
                    for i, alg in enumerate(algorithms):
                        try:
                            result = wr.run_benchmark(alg, length, keysize)
                            ok = True
                        except Exception as e:
                            result = str(e)
                            ok = False
                        self.after(
                            0,
                            lambda alg=alg, result=result, ok=ok, i=i: self._benchmark_row(
                                results_box, bar, status, alg, result, ok, i + 1, len(algorithms)
                            )
                        )
                    self.after(0, lambda: btn.configure(state="normal"))

                threading.Thread(target=target, daemon=True).start()

            self._confirm_large_rsa(keysize, launch)

        btn.configure(command=do_run)

    def _benchmark_row(self, box, bar, status, alg, result, ok, done, total):
        box.configure(state="normal")

        # Section banners — printed once, right before the first algorithm
        # of each category.
        if alg in AVAIL_HASH_STR and AVAIL_HASH_STR.index(alg) == 0:
            box.insert("end", "========== HASH ALGORITHMS ==========\n")
        if alg in AVAIL_ALG and AVAIL_ALG.index(alg) == 0:
            box.insert("end", "\n========== CRYPTO ALGORITHMS ==========\n")
        if alg in AVAIL_SIGN_ALG and AVAIL_SIGN_ALG.index(alg) == 0:
            box.insert("end", "\n========== SIGNING ALGORITHMS ==========\n")
        if alg in AVAIL_RANDOM_STR and AVAIL_RANDOM_STR.index(alg) == 0:
            box.insert("end", "\n========== RANDOM ALGORITHMS ==========\n")

        if not ok:
            # Show exactly which algorithm the error came from, and wrap the
            # (often long) formatted CryptoError/GeneralError message with a
            # hanging indent so the table stays readable.
            wrapped = textwrap.fill(
                result,
                width=96,
                subsequent_indent=" " * 22,
                break_long_words=False)
            box.insert("end", f"{alg:<22}{wrapped}\n")
        elif alg in AVAIL_ALG or alg in AVAIL_SIGN_ALG:
            (enc, dec), keygen = result
            box.insert(
                "end", f"{
                    enc[0]:<22}{
                    enc[1]}\n{
                    dec[0]:<22}{
                    dec[1]}\n{
                        keygen[0]:<22}{
                            keygen[1]}\n")
        else:
            name, value = result
            box.insert("end", f"{name:<22}{value}\n")

        box.see("end")
        box.configure(state="disabled")
        bar.set(done / total)
        status.configure(
            text=f"{done}/{total} complete",
            text_color=THEME["slight_gray"] if done < total else SUCCESS
        )

    # ------------------------------------------------------------------ #
    # Secure delete / wipe free space
    # ------------------------------------------------------------------ #

    def _build_sdelete(self):
        self._page_header(
            "trash",
            "Secure Delete",
            "Permanently remove a file with multi-pass overwrite.")
        page = self._page(row=1)

        row = 0
        self._field_label(page, row, "File to shred")
        row += 1
        file_entry = self._entry(page, row, "File to permanently remove")
        shred_paths = []
        self._file_row(
            page,
            row,
            file_entry,
            multiple=True,
            selected=shred_paths)
        row += 1

        self._field_label(page, row, "Overwrite pattern")
        row += 1
        method_var, _ = self._option(page, row, OVERWRITE_OPTIONS)
        row += 1

        self._field_label(
            page, row, "Random source (used by 'random'/'gutmann')")
        row += 1
        rand_var, _ = self._option(page, row, AVAIL_RANDOM_STR)
        row += 1

        self._field_label(page, row, "Passes")
        row += 1
        repeat_entry = self._entry(page, row, default="1")
        row += 1

        self._field_label(page, row, "Chunk size (KB)")
        row += 1
        chunk_entry = self._entry(page, row, default="1024")
        row += 1

        zero_var = self._checkbox(
            page, row, "Zero-out after overwriting", True)
        row += 1
        ctk.CTkLabel(
            page, text="Zero-out adds one additional overwrite pass.",
            text_color=THEME["gray_text"], font=self._font(10), anchor="w"
        ).grid(row=row, column=0, columnspan=2, sticky="w", pady=(0, 4))
        row += 1
        delete_var = self._checkbox(
            page, row, "Rename and delete the file afterwards", True)
        row += 1

        btn, bar, status = self._run_row(page, row, "Shred File", None)

        def do_run():
            paths = shred_paths or [
                path.strip() for path in file_entry.get().split(",") if path.strip()]
            if not paths:
                self._error_win("Missing information", "Please choose a file.")
                return
            try:
                chunksize = int(chunk_entry.get())
                repeat = int(repeat_entry.get())
            except ValueError:
                self._error_win("Invalid input",
                                "Chunk size and passes must be numeric.")
                return

            if method_var.get() == "gutmann" and repeat > 1:
                warning = CTkMessagebox(
                    self,
                    icon="warning",
                    title="Gutmann already uses 32 passes",
                    message="Gutmann performs 32 passes. Additional passes repeat the full sequence. Continue?",
                    option_1="Cancel",
                    option_2="Continue")
                if warning.get() != "Continue":
                    return

            confirm = CTkMessagebox(
                self,
                icon="warning",
                title="This cannot be undone",
                message=f"{
                    len(paths)} selected file(s) will be overwritten and permanently deleted. Continue?",
                option_1="Cancel",
                option_2="Shred")
            if confirm.get() != "Shred":
                return

            def work():
                return wr.secure_delete_paths(
                    paths,
                    method_var.get(),
                    zero_var.get(),
                    delete_var.get(),
                    chunksize,
                    rand_var.get(),
                    repeat)

            self._run_async(
                work,
                btn,
                bar,
                status,
                on_success=lambda deleted: status.configure(
                    text=f"{
                        len(deleted)} file(s) securely removed.",
                    text_color=SUCCESS),
                start_msg="Shredding…",
            )

        btn.configure(command=do_run)

    def _build_wipe_space(self):
        self._page_header(
            "hard-drive",
            "Wipe Free Space",
            "Overwrite unused disk space so deleted files can't be recovered.")
        page = self._page(row=1)

        try:
            partitions = wr.list_partitions()
        except Exception:
            partitions = []
        device_values = [p.device for p in partitions] or [
            "No partitions found"]

        row = 0
        self._field_label(page, row, "Partition / device")
        row += 1
        device_var, _ = self._option(page, row, device_values)
        row += 1

        self._field_label(page, row, "Fill pattern")
        row += 1
        fill_var, _ = self._option(page, row, ["Random data", "Zeros"])
        row += 1

        self._field_label(page, row, "Random source (used by 'Random data')")
        row += 1
        rand_var, _ = self._option(page, row, AVAIL_RANDOM_STR)
        row += 1

        self._field_label(page, row, "Chunk size (KB)")
        row += 1
        chunk_entry = self._entry(page, row, default="1024")
        row += 1

        btn, bar, status = self._run_row(page, row, "Wipe Free Space", None)

        def do_run():
            device = device_var.get()
            if device not in [p.device for p in partitions]:
                self._error_win(
                    "No device", "No writable partition was found.")
                return
            try:
                chunksize = int(chunk_entry.get())
            except ValueError:
                self._error_win("Invalid input", "Chunk size must be numeric.")
                return

            confirm = CTkMessagebox(
                self,
                icon="warning",
                title="This may take a while",
                message=f"This will fill all free space on '{device}' before removing the temporary file. Continue?",
                option_1="Cancel",
                option_2="Wipe")
            if confirm.get() != "Wipe":
                return

            def work():
                wr.wipe_free_space(
                    device,
                    chunksize,
                    fill_var.get() == "Zeros",
                    rand_var.get())
                return device

            self._run_async(
                work,
                btn,
                bar,
                status,
                on_success=lambda d: status.configure(
                    text=f"Free space on '{d}' has been wiped.",
                    text_color=SUCCESS),
                start_msg="Wiping free space… this can take a while.",
            )

        btn.configure(command=do_run)

    # ------------------------------------------------------------------ #
    # About
    # ------------------------------------------------------------------ #

    def _build_about(self):
        wrap = ctk.CTkFrame(self.content, fg_color="transparent")
        wrap.grid(row=0, column=0, sticky="new", padx=32, pady=(36, 30))
        wrap.grid_columnconfigure(0, weight=1, minsize=0)

        hero = ctk.CTkFrame(wrap, fg_color="transparent")
        hero.grid(row=0, column=0, sticky="ew")
        hero.grid_columnconfigure(1, weight=1)

        try:
            icon = ctk.CTkImage(
                Image.open(ICON_PNG),
                Image.open(ICON_PNG),
                (84, 84)
            )
            ctk.CTkLabel(
                hero,
                width=84,
                image=icon,
                text="",
                anchor="nw").grid(
                row=0,
                column=0,
                rowspan=3,
                sticky="nw")
        except Exception:
            pass

        ctk.CTkLabel(
            hero,
            text="Ghostbytes",
            text_color=THEME["content_text"],
            font=self._font(
                30,
                "bold"),
            anchor="w").grid(
            row=0,
            column=1,
            sticky="sw",
            padx=(
                18,
                0))
        ctk.CTkLabel(
            hero,
            text="File Encryption Utility",
            text_color=ACCENT,
            font=self._font(
                14,
                "bold"),
            anchor="w").grid(
            row=1,
            column=1,
            sticky="nw",
            padx=(
                18,
                0))
        ctk.CTkLabel(
            hero,
            text="A military-grade cryptographic toolkit for file encryption, key "
            "management, and secure data handling — built for privacy, from the "
            "ground up.",
            text_color=THEME["slight_gray"],
            font=self._font(13),
            anchor="w",
            justify="left",
            wraplength=560).grid(
            row=2,
            column=1,
            sticky="nw",
            padx=(
                18,
                0),
            pady=(
                6,
                0))

        chips = ctk.CTkFrame(wrap, fg_color="transparent")
        chips.grid(row=1, column=0, sticky="w", pady=(20, 0))
        for i, cap in enumerate(CAPABILITIES):
            chip = ctk.CTkFrame(
                chips,
                fg_color=ACCENT_TINT,
                border_width=1,
                border_color=ACCENT_BORDER,
                corner_radius=999)
            chip.grid(
                row=0, column=i, sticky="w", padx=(
                    0 if i == 0 else 8, 0))
            ctk.CTkLabel(
                chip,
                text=cap,
                text_color=ACCENT,
                font=self._font(
                    11,
                    "bold")).pack(
                padx=14,
                pady=6)

        divider = ctk.CTkFrame(wrap, height=1, fg_color=THEME["box_border"])
        divider.grid(row=2, column=0, sticky="ew", pady=(28, 22))

        info = ctk.CTkFrame(wrap, fg_color="transparent")
        info.grid(row=3, column=0, sticky="ew")
        info.grid_columnconfigure(2, weight=1)

        for i, (icon_name, label, value) in enumerate(ABOUT_BOX_CONTENT):
            row_pad = (8, 4)

            icon_badge = ctk.CTkLabel(
                info, text="", width=20, image=icon_to_ctkimage(
                    icon_name, fill=ACCENT, scale_to_width=14))
            icon_badge.grid(
                row=i, column=0, sticky="w", padx=(
                    0, 10), pady=row_pad)

            ctk.CTkLabel(
                info,
                text=label,
                text_color=THEME["slight_gray"],
                font=self._font(12),
                anchor="w",
                width=70).grid(
                row=i,
                column=1,
                sticky="w",
                pady=row_pad)

            content = ctk.CTkLabel(
                info,
                text=value,
                text_color=THEME["content_text"],
                font=self._mono_font(12),
                justify="left",
                anchor="w")
            content.grid(
                row=i, column=2, sticky="w", padx=(
                    0, 20), pady=row_pad)

            if label == "Source":
                content.configure(text_color=ACCENT, cursor="hand2")
                content.bind(
                    "<Button-1>",
                    lambda _e,
                    url=value: webbrowser.open_new_tab(url))

    # ------------------------------------------------------------------ #
    # Shared "every CryptoConfig field is editable" advanced-settings block
    # ------------------------------------------------------------------ #

    def _build_config_fields(self, inner):
        fields = {}
        fields["hash"], hash_menu = self._option_grid(
            inner, 0, AVAIL_HASH_STR, label="Hash function")
        fields["store_iv"], _ = self._option_grid(
            inner, 1, ["append", "prepend"], label="Store IV / tag")
        fields["mac_len"] = self._entry_grid(
            inner, 2, "MAC length (4–16 bytes)", "16")
        fields["rand_func"], rand_menu = self._option_grid(
            inner, 3, AVAIL_RANDOM_STR, label="Random function")
        fields["kdf_salt"] = self._entry_grid(
            inner, 4, "KDF salt", CryptoConfig.kdf_salt.decode(
                "utf-8", "replace"), mono=True)
        fields["kdf_time"] = self._entry_grid(inner, 5, "KDF time cost", "16")
        fields["kdf_mem"] = self._entry_grid(
            inner, 6, "KDF memory (MB)", "128")
        fields["kdf_par"] = self._entry_grid(inner, 7, "KDF parallelism", "8")
        note = ctk.CTkLabel(
            inner,
            text="The KDF salt must match on every system that needs to decrypt this "
            "data — leave it default unless you control both ends.",
            text_color=THEME["gray_text"],
            font=self._font(10),
            anchor="w",
            justify="left",
            wraplength=380)
        note.grid(
            row=8, column=0, columnspan=2, sticky="w", padx=(
                12, 12), pady=(
                2, 10))
        fields["hash_widgets"] = [
            hash_menu, hash_menu.master.grid_slaves(
                row=0, column=0)[0]]
        fields["rand_widgets"] = [
            rand_menu, rand_menu.master.grid_slaves(
                row=3, column=0)[0]]
        fields["kdf_widgets"] = [
            fields["kdf_salt"], fields["kdf_salt"]._label_widget,
            fields["kdf_time"], fields["kdf_time"]._label_widget,
            fields["kdf_mem"], fields["kdf_mem"]._label_widget,
            fields["kdf_par"], fields["kdf_par"]._label_widget, note,
        ]
        return fields

    def _config_from_fields(
            self,
            fields,
            allow_empty_salt=False,
            algorithm=CryptoConfig.algorithm):
        try:
            mac_len = int(fields["mac_len"].get())
            kdf_time = int(fields["kdf_time"].get())
            kdf_mem = int(fields["kdf_mem"].get())
            kdf_par = int(fields["kdf_par"].get())
        except ValueError as exc:
            raise invalid_argument(
            "advanced settings",
            "must contain numeric MAC and KDF values") from exc

        if not 4 <= mac_len <= 16:
            raise invalid_argument(
                "MAC length", "must be between 4 and 16 bytes")
        if kdf_time < 1 or kdf_mem < 1 or kdf_par < 1:
            raise invalid_argument("KDF settings", "must all be at least 1")

        salt = fields["kdf_salt"].get()
        if not salt:
            if not allow_empty_salt:
                raise invalid_argument("KDF salt", "cannot be empty")
            salt = CryptoConfig.kdf_salt.decode("utf-8")
        elif salt.startswith("base64:"):
            try:
                salt = base64.b64decode(salt[7:], validate=True)
            except ValueError as exc:
                raise invalid_argument(
                    "KDF salt", "must contain valid base64 data") from exc

        return wr.build_config(
            algorithm=algorithm,
            store_iv=fields["store_iv"].get(),
            mac_len=mac_len,
            kdf_salt=salt,
            kdf_time_cost=kdf_time,
            kdf_memory_cost=kdf_mem * 1024,
            kdf_parallelism=kdf_par,
            hash_func_str=fields["hash"].get(),
            rand_func=fields["rand_func"].get(),
        )

    # ------------------------------------------------------------------ #
    # Large-RSA-key warning (session-scoped "don't remind me")
    # ------------------------------------------------------------------ #

    def _confirm_large_rsa(self, size_bits, on_continue):
        if size_bits <= RSA_SIZE_WARNING_THRESHOLD or self._suppress_rsa_warning:
            on_continue()
            return

        msg = CTkMessagebox(
            self, icon="warning", title="Large RSA key",
            message=(
                f"This uses a {size_bits}-bit RSA key. Generating RSA keys in Python is "
                f"inefficient at this size. For better speed and reliability, use "
                f"OpenSSL instead — e.g.\n\n"
                f"    openssl genrsa -out key.pem {size_bits}\n\n"
                f"and importing the resulting file here.\n\nContinue anyway?"
            ),
            option_1="Cancel", option_2="Continue", option_3="Continue, don't ask again",
        )
        choice = msg.get()
        if choice == "Continue":
            on_continue()
        elif choice == "Continue, don't ask again":
            self._suppress_rsa_warning = True
            on_continue()
        # Cancel / closed -> do nothing

    # ------------------------------------------------------------------ #
    # Generic form-building helpers used by every tool page
    # ------------------------------------------------------------------ #

    def _page_header(self, icon, title, subtitle=None):
        header = ctk.CTkFrame(self.content, fg_color="transparent")
        header.grid(row=0, column=0, sticky="new", padx=32, pady=(28, 18))
        header.grid_columnconfigure(1, weight=1)

        badge = ctk.CTkFrame(
            header,
            width=40,
            height=40,
            corner_radius=10,
            fg_color=ACCENT_TINT,
            border_width=1,
            border_color=ACCENT_BORDER)
        badge.grid(row=0, column=0, rowspan=2, sticky="nw")
        badge.grid_propagate(False)
        ctk.CTkLabel(
            badge,
            text="",
            image=icon_to_ctkimage(
                icon,
                fill=ACCENT,
                scale_to_width=18)).place(
            relx=0.5,
            rely=0.5,
            anchor="center")

        ctk.CTkLabel(
            header, text=title, text_color=THEME["content_text"],
            font=self._font(21, "bold"), anchor="w"
        ).grid(row=0, column=1, sticky="sw", padx=(12, 0))

        if subtitle:
            ctk.CTkLabel(
                header, text=subtitle, text_color=THEME["slight_gray"],
                font=self._font(12), anchor="w", justify="left"
            ).grid(row=1, column=1, sticky="nw", padx=(12, 0))

        divider = ctk.CTkFrame(header, height=1, fg_color=THEME["box_border"])
        divider.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(18, 0))

        return header

    def _page(self, row=1):
        """A plain (unbordered) content area that page fields sit directly
        on — grouped with `_section` headings rather than boxed in a card,
        so input areas read as one continuous form."""
        frame = ctk.CTkFrame(self.content, fg_color="transparent")
        frame.grid(row=row, column=0, sticky="new", padx=32, pady=(0, 36))
        frame.grid_columnconfigure(0, weight=3)
        frame.grid_columnconfigure(1, weight=1, minsize=120)
        return frame

    def _section(self, parent, row, title):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(18, 8))
        tick = ctk.CTkFrame(
            wrap,
            width=3,
            height=13,
            fg_color=ACCENT,
            corner_radius=2)
        tick.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            wrap,
            text=title,
            text_color=THEME["content_text"],
            font=self._font(
                12,
                "bold"),
            anchor="w").grid(
            row=0,
            column=1,
            sticky="w",
            padx=(
                8,
                0))
        return wrap

    def _field_label(self, parent, row, text):
        ctk.CTkLabel(
            parent, text=text, text_color=THEME["slight_gray"],
            font=self._font(11), anchor="w"
        ).grid(row=row, column=0, columnspan=2, sticky="w", pady=(8, 3))

    def _entry(self, parent, row, placeholder="", show=None, default=""):
        entry = ctk.CTkEntry(
            parent, placeholder_text=placeholder, show=show,
            fg_color=THEME["box_color"], border_color=THEME["box_border"],
            text_color=THEME["content_text"]
        )
        if default:
            entry.insert(0, default)
        entry.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(0, 2))
        return entry

    def _file_row(self, parent, row, entry, save=False, dir_only=False, filetypes=(
            ("All files", "*.*"),), multiple=False, selected=None, on_browse=None):
        entry.grid_configure(columnspan=1)

        def browse():
            if dir_only:
                path = filedialog.askdirectory()
            elif multiple:
                paths = filedialog.askopenfilenames(filetypes=filetypes)
                if paths:
                    entry.delete(0, "end")
                    entry.insert(0, ", ".join(paths))
                    if selected is not None:
                        selected.clear()
                        selected.extend(paths)
                    if on_browse:
                        on_browse()
                return
            elif save:
                path = filedialog.asksaveasfilename(filetypes=filetypes)
            else:
                path = filedialog.askopenfilename(filetypes=filetypes)
            if path:
                entry.delete(0, "end")
                entry.insert(0, path)
                if on_browse:
                    on_browse()

        button = self._ghost_button(parent, "Browse", browse, width=80)
        button.grid(row=row, column=1, sticky="e", padx=(8, 0), pady=(0, 2))
        return button

    def _option(self, parent, row, values, default=None, command=None):
        var = ctk.StringVar(value=default or values[0])
        menu = ctk.CTkOptionMenu(
            parent,
            values=values,
            variable=var,
            fg_color=THEME["box_color"],
            button_color=ACCENT,
            button_hover_color=ACCENT_HOVER,
            text_color=THEME["content_text"],
            dropdown_fg_color=THEME["box_color"],
            dropdown_hover_color=ACCENT_TINT,
            command=command)
        menu.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(0, 2))
        return var, menu

    def _option_grid(self, parent, row, values, label=None, default=None):
        if label:
            ctk.CTkLabel(
                parent,
                text=label,
                text_color=THEME["slight_gray"],
                font=self._font(11),
                anchor="w").grid(
                row=row,
                column=0,
                sticky="w",
                padx=(
                    12,
                    4),
                pady=4)
        var = ctk.StringVar(value=default or values[0])
        menu = ctk.CTkOptionMenu(
            parent,
            values=values,
            variable=var,
            fg_color=THEME["content_bg"],
            button_color=ACCENT,
            button_hover_color=ACCENT_HOVER,
            text_color=THEME["content_text"],
            dropdown_fg_color=THEME["content_bg"],
            dropdown_hover_color=ACCENT_TINT,
            width=170)
        col = 1 if label else 0
        span = 1 if label else 2
        menu.grid(
            row=row,
            column=col,
            columnspan=span,
            sticky="e",
            padx=(
                4,
                12),
            pady=4)
        return var, menu

    def _entry_grid(self, parent, row, label, default="", mono=False):
        label_widget = ctk.CTkLabel(
            parent,
            text=label,
            text_color=THEME["slight_gray"],
            font=self._font(11),
            anchor="w")
        label_widget.grid(row=row, column=0, sticky="w", padx=(12, 4), pady=4)
        entry = ctk.CTkEntry(
            parent,
            fg_color=THEME["content_bg"],
            border_color=THEME["box_border"],
            text_color=THEME["content_text"],
            width=170,
            font=self._mono_font(11) if mono else self._font(11))
        if default:
            entry.insert(0, default)
        entry.grid(row=row, column=1, sticky="e", padx=(4, 12), pady=4)
        entry._label_widget = label_widget
        return entry

    def _checkbox(self, parent, row, text, default=False):
        var = ctk.BooleanVar(value=default)
        ctk.CTkCheckBox(
            parent,
            text=text,
            variable=var,
            text_color=THEME["content_text"],
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            checkmark_color=ACCENT_ON).grid(
            row=row,
            column=0,
            columnspan=2,
            sticky="w",
            pady=4)
        return var

    def _advanced(self, parent, row, build_fn):
        """A collapsible "Advanced settings" section — this is where every
        CryptoConfig field lives. `build_fn(inner)` populates the (initially
        hidden) tinted inner panel with its own 2-column grid."""
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        wrap.grid_columnconfigure(0, weight=1)

        inner = ctk.CTkFrame(
            wrap,
            fg_color=ACCENT_TINT,
            border_width=1,
            border_color=ACCENT_BORDER,
            corner_radius=THEME["corner_rad"])
        inner.grid_columnconfigure(0, weight=1)
        inner.grid_columnconfigure(1, weight=1)

        state = {"open": False}

        def toggle():
            state["open"] = not state["open"]
            if state["open"]:
                inner.grid(row=1, column=0, sticky="ew", pady=(8, 0))
                btn.configure(
                    text="▾  Advanced settings")
            else:
                inner.grid_forget()
                btn.configure(
                    text="▸  Advanced settings")

        btn = ctk.CTkButton(
            wrap,
            text="▸  Advanced settings",
            anchor="w",
            fg_color="transparent",
            hover_color=THEME["box_color"],
            text_color=ACCENT,
            font=self._font(
                12,
                "bold"),
            command=toggle)
        btn.grid(row=0, column=0, sticky="ew")

        build_fn(inner)
        return inner

    def _run_row(self, parent, row, text, command):
        bar = ctk.CTkProgressBar(
            parent,
            mode="indeterminate",
            progress_color=ACCENT)
        bar.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        bar.grid_remove()

        status = ctk.CTkLabel(
            parent,
            text="",
            text_color=THEME["slight_gray"],
            font=self._font(11),
            anchor="w")
        status.grid(row=row + 1, column=0, sticky="w", pady=(6, 0))

        btn = self._primary_button(parent, text, command)
        btn.grid(row=row + 1, column=1, sticky="e", pady=(6, 0))
        return btn, bar, status

    def _primary_button(self, parent, text, command=None, width=None):
        return ctk.CTkButton(
            parent, text=text, command=command, width=width or 140,
            fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ACCENT_ON,
            font=self._font(13, "bold")
        )

    def _ghost_button(self, parent, text, command=None, width=80):
        return ctk.CTkButton(
            parent, text=text, command=command, width=width,
            fg_color=THEME["box_color"], hover_color=ACCENT_TINT,
            border_width=1, border_color=THEME["box_border"],
            text_color=THEME["content_text"]
        )

    # ------------------------------------------------------------------ #
    # Background work / error handling
    # ------------------------------------------------------------------ #

    def _run_async(
            self,
            work,
            button,
            bar,
            status,
            on_success=None,
            start_msg="Working…"):
        """Run `work()` on a background thread so the GUI stays responsive.
        `work` must be a zero-argument callable (use a lambda/closure to bind
        arguments). Any `CryptoError`/`GeneralError`/other exception raised
        is caught and shown in an error dialog; on success `on_success` is
        called (on the main thread) with the return value of `work`.
        """
        button.configure(state="disabled")
        bar.grid()
        bar.start()
        status.configure(text=start_msg, text_color=THEME["slight_gray"])

        def target():
            try:
                result = work()
            except Exception as e:
                # `e` is cleared once the except block ends, so capture it now
                message = str(e)
                self.after(
                    0, lambda: self._async_fail(
                        button, bar, status, message))
                return
            self.after(
                0,
                lambda: self._async_ok(
                    button,
                    bar,
                    status,
                    result,
                    on_success))

        threading.Thread(target=target, daemon=True).start()

    def _async_fail(self, button, bar, status, message):
        bar.stop()
        bar.grid_remove()
        button.configure(state="normal")
        status.configure(text=f"Failed: {message}", text_color=DANGER)
        self._error_win("Operation Failed", message)

    def _async_ok(self, button, bar, status, result, on_success):
        bar.stop()
        bar.grid_remove()
        button.configure(state="normal")
        status.configure(text="Done.", text_color=SUCCESS)
        if on_success:
            on_success(result)

    def _error_win(self, title, content, _exit=False):
        msg = CTkMessagebox(
            self,
            icon="cancel",
            title=title,
            message=content,
            option_1="OK")
        if _exit and msg.get() is not None:
            sys.exit(1)

    def _font(self, size=12, weight="normal", underline=False):
        return ctk.CTkFont(
            family=THEME["font"],
            size=size,
            weight=weight,
            underline=underline,
        )

    def _mono_font(self, size=12, weight="normal"):
        return ctk.CTkFont(family=MONO_FONT, size=size, weight=weight)

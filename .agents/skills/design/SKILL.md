---
name: design
description: "Design and implement polished desktop UIs with CustomTkinter and Tkinter. Use for visual redesigns, new screens, forms, dashboards, navigation, theme systems, responsive layouts, accessibility, and UI polish in Python desktop applications."
argument-hint: "Describe the screen, workflow, or existing CustomTkinter UI to improve."
---

# CustomTkinter UI Design

Create desktop interfaces that feel deliberate, calm, and easy to scan. Prefer the existing application's visual language when working in a repository; use this skill to improve hierarchy and usability rather than replacing a coherent design system for novelty.

## When to Use

- Build or redesign a CustomTkinter or Tkinter window, panel, form, settings view, dashboard, or navigation shell.
- Establish reusable colors, typography, spacing, radii, and component states.
- Improve a UI that technically works but feels cluttered, flat, inconsistent, or difficult to navigate.
- Review desktop layout behavior at different window sizes and keyboard/mouse interaction states.

## Workflow

### 1. Inspect the Existing Surface

Before editing, identify:

- The top-level `CTk` window and the function or class that owns the screen.
- Existing theme constants, fonts, icon helpers, shared wrappers, and component factories.
- The primary user task, the most important action, and the expected empty, loading, success, warning, and error states.
- Whether the application already has a palette or interaction pattern that should be preserved.

State one local design hypothesis, such as: "The screen feels dense because every control has equal visual weight; grouping inputs and separating the primary action should improve scanability." Make the smallest change that can test it.

### 2. Establish Design Tokens

Keep visual decisions centralized rather than scattering literals through widget construction. Define or reuse tokens for:

- Background, surface, elevated surface, border, primary text, muted text, accent, accent hover, danger, warning, and success.
- Font families and sizes for title, section heading, body, label, helper text, and monospace data.
- Spacing steps, control heights, corner radii, border widths, and sidebar/content widths.

Use a restrained palette with enough contrast between the application background, panels, controls, and text. A dark theme is not required; when one exists, avoid making every element the same near-black value. Use one clear accent for focus, selection, and primary actions, plus semantic colors only for semantic states.

### 3. Compose the Layout Around the Task

- Start with a stable grid: configure row and column weights explicitly and use `sticky="nsew"` where content should expand.
- Separate navigation, context/header, working content, and supporting information.
- Use whitespace and section headings to group related controls before adding borders or cards.
- Give the primary action a predictable location and visual priority. Keep destructive actions visually distinct and require confirmation when appropriate.
- Use `CTkScrollableFrame` for content that can exceed the window; keep toolbars and navigation fixed when that supports the workflow.
- Avoid nesting decorative cards inside cards. Use a framed panel only when it clarifies ownership, grouping, or input/output separation.
- For repeated items, use a consistent row or grid component with stable dimensions so labels and icons do not cause layout jumps.

For a form, prefer this order: title and short context, grouped inputs, helper or validation text near the relevant control, then the action row. For a dashboard, put the current status and next action before secondary metrics.

### 4. Make Controls Feel Intentional

- Use `CTkButton` for clear commands, `CTkCheckBox` or `CTkSwitch` for binary settings, segmented button groups for a small number of modes, and `CTkComboBox` or menus for option sets.
- Use icons when they improve recognition, but pair unfamiliar icons with text or a tooltip. Do not use an icon as decoration when it competes with the label.
- Keep control heights, padding, and corner radii consistent within a view.
- Show focus, hover, selected, disabled, and pressed states with changes in color, border, text, or icon treatment. Never communicate state through color alone.
- Disable actions only when the reason is apparent; otherwise show concise helper text explaining what is missing.
- Keep long-running operations responsive by moving work off the UI thread and updating widgets through Tkinter's event loop with `after`.

### 5. Handle Data and Feedback Clearly

- Put validation feedback beside the field that needs attention and preserve the user's input.
- Use status text for routine progress, dialogs for consequential confirmations or blocking failures, and a persistent result area for output the user may copy or inspect.
- Distinguish input, generated output, and logs with labels and surface treatments rather than relying on color alone.
- Make empty states useful: explain what the user can do next and provide the relevant action.
- Ensure error text wraps or has enough width; do not let it resize neighboring controls unpredictably.

### 6. Check Window Behavior

Test the smallest supported window, the normal starting size, and a wider window. Verify that:

- The main task remains visible without overlap or clipped labels.
- Grid weights, minimum sizes, and scroll regions behave as intended.
- Buttons do not resize when state text changes.
- Long labels, translated text, validation messages, and empty lists have room to render.
- Keyboard focus order is sensible and Enter/Escape behavior is safe where implemented.
- The window remains usable with system scaling and a non-default appearance mode.

Prefer explicit `minsize`, `grid_propagate(False)` only when a fixed region is intentional, and `wraplength` for explanatory text. Avoid placing important controls with absolute coordinates.

## Implementation Patterns

Use a small theme module and component helpers:

```python
COLORS = {
	"background": "#101315",
	"surface": "#181d20",
	"border": "#2a3438",
	"text": "#e8f0ee",
	"muted": "#91a19e",
	"accent": "#1fb6a6",
	"accent_hover": "#189485",
	"danger": "#e5484d",
}

SPACING = {"xs": 4, "sm": 8, "md": 16, "lg": 24}
```

Keep screen construction readable by extracting repeated rows or panels into functions such as `build_section(parent, ...)` or `create_action_button(parent, ...)`. Pass values and callbacks into those helpers instead of coupling them to global widget state.

When extending an existing application, follow its established imports, icon library, naming style, and event model. Do not introduce a new UI framework or a second competing theme for a single screen.

## Validation Checklist

After implementation:

1. Run a syntax or import check for the touched Python files.
2. Launch the application or the smallest reproducible window and exercise the main workflow.
3. Resize the window and inspect hover, focus, disabled, validation, success, error, and empty states.
4. Check the terminal for Tkinter callback exceptions and thread-related errors.
5. Review the diff for duplicated color literals, accidental layout regressions, and unrelated formatting changes.

For a visual review, capture the window at the supported sizes when the environment permits it. Treat clipped text, inaccessible actions, inconsistent spacing, and missing feedback as correctness issues, not cosmetic details.

## Completion Criteria

A design task is complete when the primary workflow is obvious, the interface maintains hierarchy at supported sizes, all meaningful states are represented, controls provide appropriate feedback, and the implementation reuses the application's theme and component patterns. Do not call a screen finished because it merely renders without exceptions.

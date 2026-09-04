# Validation Notes

- The live landing-page theme control changed the running application from dark mode to light mode.
- After the live toggle, the control label changed to `Dark`, which correctly indicates that light mode is active and the next action would return to dark mode.
- Reloading the same page kept light mode active, confirming persistence through local storage.
- Light and dark landing, sign-in, and workspace views were visually checked at mobile size. Light and dark landing/workspace views were also checked at desktop size.
- Both light and dark sign-in gateway screens were also checked at desktop size. The terminal panels, contrast, and theme controls remained readable in each reviewed view.
- The trusted OAuth flow returned from the secure sign-in gateway to the protected Threat OS workspace. The authenticated workspace showed the signed-in session controls, including the user area and sign-out action.
- The email-warning chart now provides each bar's own time and warning count. Selecting the 08:00 bar changed the readout from the default 15:00 / 16 warnings to 08:00 / 7 warnings, confirming the chart is no longer repeating the same number for every bar.
- The same chart interaction was verified in light mode: selecting the 18:00 bar changed the readout to 18:00 / 14 warnings while keeping the selected bar visibly highlighted.

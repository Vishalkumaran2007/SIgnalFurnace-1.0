import matrixFieldSource from "@/threeui/shaders/neuform-isolated/sources/matrix-field.html?raw";

type LaserCollectionFrameProps = {
  variant?: "matrix-field";
  speed?: number;
  size?: number;
  length?: number;
  density?: number;
  opacity?: number;
  hue?: number;
  saturation?: number;
  brightness?: number;
};

/**
 * Matrix Junction is rendered from the verified ThreeUI canonical source. The
 * isolated frame prevents its authored document-level styles from affecting
 * the application while retaining its own WebGL lifecycle and pointer motion.
 */
export function LaserCollection({
  variant = "matrix-field",
  speed = 1,
  size = 1,
  length = 1,
  density = 1,
  opacity = 1,
  hue = 0,
  saturation = 1,
  brightness = 1,
}: LaserCollectionFrameProps) {
  const controls = JSON.stringify({ variant, speed, size, length, density, opacity, hue, saturation, brightness });
  const source = matrixFieldSource.replace("</head>", `<script>window.__SF_CONTROLS=${controls};</script></head>`);

  return <iframe className="laser-collection-frame" title="Decorative Matrix Junction background" srcDoc={source} tabIndex={-1} aria-hidden="true" />;
}

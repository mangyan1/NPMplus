import { useEffect, useState } from "react";
import styles from "./AnimatedLogo.module.css";

// the npmplus mark with three hexagon comets orbiting it: the animation is
// smil baked into the svg asset, so the browser plays it even inside an
// <img>. smil cannot be paused from css, so for users who prefer reduced
// motion the animated image is not rendered at all - a static mark replaces it
const AnimatedLogo = () => {
	const [reducedMotion, setReducedMotion] = useState(false);

	useEffect(() => {
		const query = window.matchMedia("(prefers-reduced-motion: reduce)");
		const update = () => setReducedMotion(query.matches);
		update();
		query.addEventListener("change", update);
		return () => query.removeEventListener("change", update);
	}, []);

	if (reducedMotion) {
		return <img className={styles.logo} src="/images/logo-no-text.svg" alt="" aria-hidden="true" />;
	}

	return <img className={styles.logo} src="/images/crowdsec-logo-animated.svg" alt="" aria-hidden="true" />;
};

export default AnimatedLogo;

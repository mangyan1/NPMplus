import { IconWorld } from "@tabler/icons-react";
import {
	BG,
	CN,
	CZ,
	DE,
	EE,
	ES,
	FR,
	HU,
	ID,
	IE,
	IT,
	JP,
	KR,
	NL,
	NO,
	PL,
	PT,
	RU,
	SK,
	TR,
	UA,
	VN,
} from "country-flag-icons/react/3x2";

const localeFlags = {
	BG,
	CN,
	CZ,
	DE,
	EE,
	ES,
	FR,
	HU,
	ID,
	IE,
	IT,
	JP,
	KR,
	NL,
	NO,
	PL,
	PT,
	RU,
	SK,
	TR,
	UA,
	VN,
};

interface FlagProps {
	className?: string;
	countryCode: string;
}
function Flag({ className, countryCode }: FlagProps) {
	countryCode = countryCode.toUpperCase();
	if (countryCode === "EN") {
		return <IconWorld className={className} width={20} />;
	}

	if (countryCode in localeFlags) {
		const FlagElement = localeFlags[countryCode as keyof typeof localeFlags];
		return <FlagElement title={countryCode} className={className} width={20} />;
	}
	console.error(`No flag for country ${countryCode} found!`);
	return null;
}

export { Flag };

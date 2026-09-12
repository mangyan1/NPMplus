import { IconWorld } from "@tabler/icons-react";
import {
	AZ,
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
	AZ,
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
	return <IconWorld className={className} width={20} />;
}

export { Flag };

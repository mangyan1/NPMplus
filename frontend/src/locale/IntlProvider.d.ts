import type { ReactElement } from "react";
import type { IntlShape } from "react-intl";

export const intl: IntlShape;
export const currentLocale: string;
export const localeOptions: string[];
export function getFlagCodeForLocale(locale?: string): string;
export function changeLocale(lang: string): void;
export function T(props: {
	id: string;
	data?: Record<string, string | number | boolean | Date | null | undefined>;
	tData?: Record<string, string>;
}): ReactElement;

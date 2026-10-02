import type NiceModal from "@ebay/nice-modal-react";
import type { NiceModalHocProps } from "@ebay/nice-modal-react";
import type { ComponentType, FC } from "react";

export interface InnerModalProps {
	visible: boolean;
	remove: () => void;
}

// The wrapper injects visible/remove; callers only pass the modal's own props.
declare const EasyModal: Omit<typeof NiceModal, "create"> & {
	create: <P extends InnerModalProps>(
		component: ComponentType<P>,
	) => FC<Omit<P, keyof InnerModalProps> & NiceModalHocProps>;
};

export default EasyModal;

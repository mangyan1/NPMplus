import { HasPermission } from "src/components";
import { ADMIN, VIEW } from "src/modules/Permissions";
import CrowdsecDashboard from "./Dashboard";

const Crowdsec = () => (
	<HasPermission section={ADMIN} permission={VIEW} pageLoading loadingNoLogo>
		<CrowdsecDashboard />
	</HasPermission>
);

export default Crowdsec;

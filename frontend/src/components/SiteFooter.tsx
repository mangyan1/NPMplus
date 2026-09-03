import { useCheckVersion } from "src/hooks";
import { T } from "src/locale";

const COMMIT_PATTERN = /^[0-9a-f]{7,40}$/i;

export function SiteFooter() {
	const { data: versionData } = useCheckVersion();

	const version = versionData?.current || "";
	const githubTag = version.split("-").slice(0, 4).join("-");
	const githubRepository = "mangyan1/NPMplus";
	const githubLinkType = COMMIT_PATTERN.test(githubTag) ? "commit" : "releases/tag";

	return (
		<footer className="footer d-print-none py-3">
			<div className="container-xl">
				<div className="row text-center align-items-center flex-row-reverse">
					<div className="col-lg-auto ms-lg-auto">
						<ul className="list-inline list-inline-dots mb-0">
							<li className="list-inline-item">
								<a
									href={`https://github.com/${githubRepository}`}
									target="_blank"
									className="link-secondary"
									rel="noopener"
								>
									<T id="footer.github" />
								</a>
							</li>
						</ul>
					</div>
					<div className="col-12 col-lg-auto mt-3 mt-lg-0">
						<ul className="list-inline list-inline-dots mb-0">
							<li className="list-inline-item">© {new Date().getFullYear()} AGPL-3.0 (and MIT)</li>
							<li className="list-inline-item">
								Fork maintained by{" "}
								<a
									href="https://github.com/mangyan1"
									rel="noreferrer"
									target="_blank"
									className="link-secondary"
								>
									mangyan1
								</a>
							</li>
							<li className="list-inline-item">
								<a href="https://jc21.com" rel="noreferrer" target="_blank" className="link-secondary">
									jc21.com
								</a>
							</li>
							<li className="list-inline-item">
								<a
									href="https://github.com/ZoeyVid"
									rel="noreferrer"
									target="_blank"
									className="link-secondary"
								>
									ZoeyVid
								</a>
							</li>
							<li className="list-inline-item">
								<T id="theme-by" />{" "}
								<a href="https://tabler.io" rel="noreferrer" target="_blank" className="link-secondary">
									Tabler
								</a>
							</li>
							<li className="list-inline-item">
								<a
									href={`https://github.com/${githubRepository}/${githubLinkType}/${githubTag}`}
									className="link-secondary"
									target="_blank"
									rel="noopener"
								>
									{" "}
									{version}{" "}
								</a>
							</li>
							{versionData?.updateAvailable && versionData?.latest && (
								<li className="list-inline-item">
									<a
										href={`https://github.com/${githubRepository}/commit/${versionData.latest}`}
										className="link-warning fw-bold"
										target="_blank"
										rel="noopener"
									>
										<T id="update-available" data={{ latestVersion: versionData.latest }} />
									</a>
								</li>
							)}
						</ul>
					</div>
				</div>
			</div>
		</footer>
	);
}

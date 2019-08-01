<?php

namespace Entity;

use Doctrine\ORM\Mapping as ORM;
use JsonSerializable;

/**
 * @ORM\Entity
 * @ORM\Table(
 *     name="AnonymusUsers",
 *     indexes={
 *     @ORM\Index(name="uName", columns={"uName"})
 *     }
 * )
 */
class AnonymusUser implements JsonSerializable
{
    /**
     * @ORM\Id @ORM\Column(type="integer", options={"unsigned": true})
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $uID;

    /**
     * @ORM\OneToMany(targetEntity="\Concrete\Core\Entity\Attribute\Value\UserValue", cascade={"remove"}, mappedBy="user")
     * @ORM\JoinColumn(name="uID", referencedColumnName="uID")
     */
    protected $attributes;

    /**
     * @ORM\Column(type="string", length=64, unique=true)
     */
    protected $uName;

    /**
     * @ORM\Column(type="datetime")
     */
    protected $uDateAdded = null;

    /**
     * @ORM\Column(type="text", nullable=true)
     */
    protected $uLastIP;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    protected $uTimezone;

    /**
     * @ORM\Column(type="string", length=32, nullable=true)
     */
    protected $uDefaultLanguage;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    protected $uLastAgent;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    protected $uGraphqlJwtAuthSecret;

    /**
     * @ORM\Column(type="boolean", nullable=true)
     */
    protected $uGraphqlJwtAuthSecretRevoked;

    /**
     * @ORM\Column(type="integer", nullable=true)
     */
    protected $uGraphqlJwtTokenNotBefore;

    /**
     * @ORM\Column(type="integer", nullable=true)
     */
    protected $uGraphqlJwtTokenExpires;

    /**
     * @ORM\Column(type="integer", nullable=true)
     */
    protected $uGraphqlJwtRefreshTokenExpires;

    /**
     * @ORM\Column(type="integer", nullable=true)
     */
    protected $uGraphqlJwtLastRequest;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    protected $uGraphqlJwtLastRequestIp;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    protected $uGraphqlJwtLastRequestAgent;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    protected $uGraphqlJwtLastRequestTimezone;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    protected $uGraphqlJwtLastRequestLanguage;

    /**
     * @ORM\Column(type="integer", nullable=true)
     */
    protected $uGraphqlJwtRequestCount;


    public function __construct()
    {
        $this->uDateAdded = new \DateTime();
    }

    /**
     * @return int
     */
    public function getUserID()
    {
        return $this->uID;
    }

    /**
     * @return string
     */
    public function getUserName()
    {
        return $this->uName;
    }

    /**
     * Gets the date a user was added to the system.
     *
     * @return \DateTime
     */
    public function getUserDateAdded()
    {
        return $this->uDateAdded;
    }

    /**
     * @return string|null
     */
    public function getUserLastIP()
    {
        return $this->uLastIP;
    }

    /**
     * @return string|null
     */
    public function getUserTimezone()
    {
        return $this->uTimezone;
    }

    /**
     * @return string|null
     */
    public function getUserDefaultLanguage()
    {
        return $this->uDefaultLanguage;
    }

    /**
     * @return string|null
     */
    public function getUserLastAgent()
    {
        return $this->uLastAgent;
    }

    /**
     * @return string|null
     */
    public function getUserGraphqlJwtAuthSecret()
    {
        return $this->uGraphqlJwtAuthSecret;
    }

    /**
     * @return boolean|null
     */
    public function getUserGraphqlJwtAuthSecretRevoked()
    {
        return $this->uGraphqlJwtAuthSecretRevoked;
    }

    /**
     * @return integer|null
     */
    public function getUserGraphqlJwtTokenNotBefore()
    {
        return $this->uGraphqlJwtTokenNotBefore;
    }

    /**
     * @return integer|null
     */
    public function getUserGraphqlJwtTokenExpires()
    {
        return $this->uGraphqlJwtTokenExpires;
    }

    /**
     * @return integer|null
     */
    public function getUserGraphqlJwtRefreshTokenExpires()
    {
        return $this->uGraphqlJwtRefreshTokenExpires;
    }

    /**
     * @return integer|null
     */
    public function getUserGraphqlJwtLastRequest()
    {
        return $this->uGraphqlJwtLastRequest;
    }

    /**
     * @return string|null
     */
    public function getUserGraphqlJwtLastRequestIp()
    {
        return $this->uGraphqlJwtLastRequestIp;
    }

    /**
     * @return string|null
     */
    public function getUserGraphqlJwtLastRequestAgent()
    {
        return $this->uGraphqlJwtLastRequestAgent;
    }

    /**
     * @return string|null
     */
    public function getUserGraphqlJwtLastRequestTimezone()
    {
        return $this->uGraphqlJwtLastRequestTimezone;
    }

    /**
     * @return string|null
     */
    public function getUserGraphqlJwtLastRequestLanguage()
    {
        return $this->uGraphqlJwtLastRequestLanguage;
    }

    /**
     * @return integer|null
     */
    public function getUserGraphqlJwtRequestCount()
    {
        return $this->uGraphqlJwtRequestCount;
    }

    /**
     * @param int $uID
     */
    public function setUserID($uID)
    {
        $this->uID = $uID;
    }

    /**
     * @param string $uName
     */
    public function setUserName($uName)
    {
        $this->uName = $uName;
    }

    /**
     * @param \DateTime $uDateAdded
     */
    public function setUserDateAdded($uDateAdded)
    {
        $this->uDateAdded = $uDateAdded;
    }

    /**
     * @param string $uLastIP
     */
    public function setUserLastIP($uLastIP)
    {
        $this->uLastIP = $uLastIP;
    }

    /**
     * @param string|null $uTimezone
     */
    public function setUserTimezone($uTimezone)
    {
        $this->uTimezone = $uTimezone;
    }

    /**
     * @param string|null $uDefaultLanguage
     */
    public function setUserDefaultLanguage($uDefaultLanguage)
    {
        $this->uDefaultLanguage = $uDefaultLanguage;
    }

    /**
     * @param string|null $uLastAgent
     */
    public function setUserLastAgent($uLastAgent)
    {
        $this->uLastAgent = $uLastAgent;
    }

    /**
     * @param string|null $uLastAgent
     */
    public function setUserGraphqlJwtAuthSecret($uGraphqlJwtAuthSecret)
    {
        $this->uGraphqlJwtAuthSecret = $uGraphqlJwtAuthSecret;
    }

    /**
     * @param boolean|null $uLastAgent
     */
    public function setUserGraphqlJwtAuthSecretRevoked($uGraphqlJwtAuthSecretRevoked)
    {
        $this->uGraphqlJwtAuthSecretRevoked = $uGraphqlJwtAuthSecretRevoked;
    }

    /**
     * @param integer|null $uLastAgent
     */
    public function setUserGraphqlJwtTokenNotBefore($uGraphqlJwtTokenNotBefore)
    {
        $this->uGraphqlJwtTokenNotBefore = $uGraphqlJwtTokenNotBefore;
    }

    /**
     * @param integer|null $uLastAgent
     */
    public function setUserGraphqlJwtTokenExpires($uGraphqlJwtTokenExpires)
    {
        $this->uGraphqlJwtTokenExpires = $uGraphqlJwtTokenExpires;
    }

    /**
     * @param integer|null $uLastAgent
     */
    public function setUserGraphqlJwtRefreshTokenExpires($uGraphqlJwtRefreshTokenExpires)
    {
        $this->uGraphqlJwtRefreshTokenExpires = $uGraphqlJwtRefreshTokenExpires;
    }

    /**
     * @param integer|null $uLastAgent
     */
    public function setUserGraphqlJwtLastRequest($uGraphqlJwtLastRequest)
    {
        $this->uGraphqlJwtLastRequest = $uGraphqlJwtLastRequest;
    }

    /**
     * @param string|null $uLastAgent
     */
    public function setUserGraphqlJwtLastRequestIp($uGraphqlJwtLastRequestIp)
    {
        $this->uGraphqlJwtLastRequestIp = $uGraphqlJwtLastRequestIp;
    }

    /**
     * @param string|null $uLastAgent
     */
    public function setUserGraphqlJwtLastRequestAgent($uGraphqlJwtLastRequestAgent)
    {
        $this->uGraphqlJwtLastRequestAgent = $uGraphqlJwtLastRequestAgent;
    }

    /**
     * @param string|null $uLastAgent
     */
    public function setUserGraphqlJwtLastRequestTimezone($uGraphqlJwtLastRequestTimezone)
    {
        $this->uGraphqlJwtLastRequestTimezone = $uGraphqlJwtLastRequestTimezone;
    }

    /**
     * @param string|null $uLastAgent
     */
    public function setUserGraphqlJwtLastRequestLanguage($uGraphqlJwtLastRequestLanguage)
    {
        $this->uGraphqlJwtLastRequestLanguage = $uGraphqlJwtLastRequestLanguage;
    }

    /**
     * @param integer|null $uLastAgent
     */
    public function setUserGraphqlJwtRequestCount($uGraphqlJwtRequestCount)
    {
        $this->uGraphqlJwtRequestCount = $uGraphqlJwtRequestCount;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return (string) $this->getUserID();
    }

    /**
     * Return the user's identifier.
     *
     * @return mixed
     */
    public function getIdentifier()
    {
        return $this->getUserID();
    }

    public function jsonSerialize()
    {
        return [
            'uID' => $this->getUserID(),
            'uName' => $this->getUserName(),
            'uDateAdded' => $this->getUserDateAdded(),
            'uLastIP' => $this->getUserLastIP(),
            'uLastAgent' => $this->getUserLastAgent(),
            'uTimezone' => $this->getUserTimezone(),
            'uDefaultLanguage' => $this->getUserDefaultLanguage(),
            'uGraphqlJwtAuthSecret' => $this->getUserGraphqlJwtAuthSecret(),
            'uGraphqlJwtAuthSecretRevoked' => $this->getUserGraphqlJwtAuthSecretRevoked(),
            'uGraphqlJwtTokenNotBefore' => $this->getUserGraphqlJwtTokenNotBefore(),
            'uGraphqlJwtTokenExpires' => $this->getUserGraphqlJwtTokenExpires(),
            'uGraphqlJwtRefreshTokenExpires' => $this->getUserGraphqlJwtRefreshTokenExpires(),
            'uGraphqlJwtLastRequest' => $this->getUserGraphqlJwtLastRequest(),
            'uGraphqlJwtLastRequestIp' => $this->getUserGraphqlJwtLastRequestIp(),
            'uGraphqlJwtLastRequestAgent' => $this->getUserGraphqlJwtLastRequestAgent(),
            'uGraphqlJwtLastRequestTimezone' => $this->getUserGraphqlJwtLastRequestTimezone(),
            'uGraphqlJwtLastRequestLanguage' => $this->getUserGraphqlJwtLastRequestLanguage(),
            'uGraphqlJwtRequestCount' => $this->getUserGraphqlJwtRequestCount(),
            'anonymus' => true
        ];
    }
}
